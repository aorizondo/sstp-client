"""
SSTP Client - Main implementation.
Orchestrates SSTP connection, PPP handling, and port binding.
"""
import logging
import threading
import select
from typing import Optional
from OpenSSL.SSL import Connection, Error, WantReadError, WantWriteError

from .handshake import SSTPHandshake
from .protocol import SSTPPacket, create_ppp_data_packet, SSTPControlPacket
from .ppp_handler import PPPHandler

logger = logging.getLogger(__name__)


class SSTPClient:
    """Main SSTP client managing connection and data flow using pyOpenSSL."""
    
    def __init__(self, server: str, username: str, password: str, port: int = 443):
        self.server = server
        self.username = username
        self.password = password
        self.port = port
        
        self.handshake = SSTPHandshake(server, port, username, password)
        self.ppp_handler = PPPHandler(username, password)
        self.ssl_sock: Optional[SSL.Connection] = None
        self.running = False
        self.recv_thread: Optional[threading.Thread] = None
    
    def connect(self):
        """Establish SSTP connection."""
        logger.info("Starting SSTP client")
        self.ssl_sock = self.handshake.connect()
        self.running = True
        
        # Configure PPP handler callbacks
        self.ppp_handler.set_sstp_send_callback(self.send_ppp_frame)
        self.ppp_handler.on_auth_success_callback = self._on_ppp_auth_success
        
        # Start receive thread
        self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self.recv_thread.start()
        
        # Start PPP connection after a small delay to ensure tunnel is ready
        logger.info("Starting PPP connection in 1s...")
        import time
        time.sleep(1)
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
                    self._handle_ppp_frame(packet.data)
            
            except Exception as e:
                if self.running:
                    logger.error(f"Error in receive loop: {e}")
                    self.running = False
                break
        
        logger.debug("Receive loop stopped")
    
    def _recv_sstp_packet(self) -> SSTPPacket:
        """Receive SSTP packet from SSL socket."""
        header = self._recv_exact(4)
        packet = SSTPPacket.unpack(header)
        
        remaining = packet.length - 4
        if remaining > 0:
            packet.data = self._recv_exact(remaining)
        
        return packet
    
    def _recv_exact(self, n: int) -> bytes:
        """Receive exactly n bytes handling SSL negotiation."""
        data = b''
        # Handle both pyOpenSSL Connection and standard socket (backwards compatibility)
        if hasattr(self.ssl_sock, 'get_socket'):
            sock = self.ssl_sock.get_socket()
        else:
            sock = self.ssl_sock
            
        timeout = sock.gettimeout()
        
        while len(data) < n:
            try:
                chunk = self.ssl_sock.recv(n - len(data))
                if not chunk:
                    raise ConnectionError("Connection closed")
                data += chunk
            except WantReadError:
                select.select([sock], [], [], timeout)
            except WantWriteError:
                select.select([], [sock], [], timeout)
            except Error as e:
                raise ConnectionError(f"SSL error: {e}")
        return data
    
    def _handle_control_packet(self, packet: SSTPPacket):
        """Handle SSTP control packet."""
        try:
            control = SSTPControlPacket.unpack(packet.data)
            logger.debug(f"Received control packet: {control.message_type.name}")
            
            # Log attributes if any
            for attr_id, attr_value in control.attributes:
                logger.debug(f"  Attribute {attr_id}: {attr_value.hex()}")
        except Exception as e:
            logger.debug(f"Received control packet (parsing failed): {len(packet.data)} bytes")
    
    def _handle_ppp_frame(self, ppp_frame: bytes):
        """Handle received PPP frame."""
        logger.debug(f"Received PPP frame: {len(ppp_frame)} bytes")
        self.ppp_handler.handle_ppp_frame_from_sstp(ppp_frame)
    
    def send_ppp_frame(self, ppp_frame: bytes):
        """Send PPP frame through SSTP tunnel."""
        if not self.ssl_sock or not self.running:
            return
            
        packet = create_ppp_data_packet(ppp_frame)
        if hasattr(self.ssl_sock, 'get_socket'):
            sock = self.ssl_sock.get_socket()
        else:
            sock = self.ssl_sock
            
        timeout = sock.gettimeout()
        
        try:
            # Simple retry loop for sendall with pyOpenSSL
            total_sent = 0
            while total_sent < len(packet):
                try:
                    sent = self.ssl_sock.send(packet[total_sent:])
                    total_sent += sent
                except WantReadError:
                    select.select([sock], [], [], timeout)
                except WantWriteError:
                    select.select([], [sock], [], timeout)
            
            logger.debug(f"Sent PPP frame ({len(ppp_frame)} bytes): {ppp_frame.hex()}")
        except Exception as e:
            logger.error(f"Error sending PPP frame: {e}")
            self.running = False
    
    def _on_ppp_auth_success(self, send_key=None, recv_key=None):
        """Called when PPP authentication succeeds."""
        logger.info("PPP authentication succeeded! Sending SSTP CALL_CONNECTED.")
        self.handshake.send_call_connected(send_key, recv_key)

    def disconnect(self):
        """Disconnect SSTP client."""
        logger.info("Disconnecting SSTP client")
        self.running = False
        
        self.ppp_handler.stop_ppp()
        
        if self.recv_thread:
            self.recv_thread.join(timeout=2.0)
        
        self.handshake.close()
        logger.info("SSTP client disconnected")
