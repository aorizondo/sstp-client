"""
SSTP Client - Main implementation.
Orchestrates SSTP connection, PPP handling, and port binding.
"""
import logging
import ssl
import threading
from typing import Optional

from .handshake import SSTPHandshake
from .protocol import SSTPPacket, create_ppp_data_packet, SSTPControlPacket
from .ppp_handler import PPPHandler

logger = logging.getLogger(__name__)


class SSTPClient:
    """Main SSTP client managing connection and data flow."""
    
    def __init__(self, server: str, username: str, password: str, port: int = 443):
        """Initialize SSTP client.
        
        Args:
            server: SSTP server hostname/IP
            username: Authentication username
            password: Authentication password
            port: Server port (default 443)
        """
        self.server = server
        self.username = username
        self.password = password
        self.port = port
        
        self.handshake = SSTPHandshake(server, port, username, password)
        self.ppp_handler = PPPHandler(username, password)
        self.ssl_sock: Optional[ssl.SSLSocket] = None
        self.running = False
        self.recv_thread: Optional[threading.Thread] = None
    
    def connect(self):
        """Establish SSTP connection."""
        logger.info("Starting SSTP client")
        self.ssl_sock = self.handshake.connect()
        self.running = True
        
        # Configure PPP handler callbacks
        self.ppp_handler.set_sstp_send_callback(self.send_ppp_frame)
        
        # Start receive thread
        self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self.recv_thread.start()
        
        # Start PPP connection
        logger.info("Starting PPP connection...")
        self.ppp_handler.start_ppp()
        
        logger.info("SSTP client connected and running")
    
    def _recv_loop(self):
        """Receive loop for SSTP packets."""
        logger.debug("Starting receive loop")
        
        while self.running:
            try:
                packet = self._recv_sstp_packet()
                
                if packet.is_control:
                    self._handle_control_packet(packet)
                else:
                    # Data packet - contains PPP frame
                    self._handle_ppp_frame(packet.data)
            
            except Exception as e:
                if self.running:
                    logger.error(f"Error in receive loop: {e}")
                    self.running = False
                break
        
        logger.debug("Receive loop stopped")
    
    def _recv_sstp_packet(self) -> SSTPPacket:
        """Receive SSTP packet from SSL socket."""
        # Read header
        header = self._recv_exact(4)
        packet = SSTPPacket.unpack(header)
        
        # Read data
        remaining = packet.length - 4
        if remaining > 0:
            data = self._recv_exact(remaining)
            packet.data = data
        
        return packet
    
    def _recv_exact(self, n: int) -> bytes:
        """Receive exactly n bytes."""
        data = b''
        while len(data) < n:
            chunk = self.ssl_sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data
    
    def _handle_control_packet(self, packet: SSTPPacket):
        """Handle SSTP control packet."""
        # TODO: Parse and handle control messages (ECHO, DISCONNECT, etc.)
        logger.debug(f"Received control packet: {len(packet.data)} bytes")
    
    def _handle_ppp_frame(self, ppp_frame: bytes):
        """Handle received PPP frame.
        
        Args:
            ppp_frame: Raw PPP frame from SSTP tunnel
        """
        logger.debug(f"Received PPP frame: {len(ppp_frame)} bytes")
        # Feed to PPP handler which will process with lwIP
        self.ppp_handler.handle_ppp_frame_from_sstp(ppp_frame)
    
    def send_ppp_frame(self, ppp_frame: bytes):
        """Send PPP frame through SSTP tunnel.
        
        Args:
            ppp_frame: Raw PPP frame to send
        """
        packet = create_ppp_data_packet(ppp_frame)
        self.ssl_sock.sendall(packet)
        logger.debug(f"Sent PPP frame: {len(ppp_frame)} bytes")
    
    def disconnect(self):
        """Disconnect SSTP client."""
        logger.info("Disconnecting SSTP client")
        self.running = False
        
        # Stop PPP
        self.ppp_handler.stop_ppp()
        
        if self.recv_thread:
            self.recv_thread.join(timeout=2.0)
        
        self.handshake.close()
        logger.info("SSTP client disconnected")
