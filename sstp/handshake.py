"""
SSTP Handshake Implementation.
Handles TCP connection, SSL/TLS handshake, HTTP negotiation, and SSTP setup.
"""
import socket
import ssl
import logging
from typing import Optional, Tuple

from .protocol import (
    create_call_connect_request,
    create_call_connected,
    SSTPPacket,
    SSTPControlPacket,
    SSTPMessageType
)

logger = logging.getLogger(__name__)


class SSTPHandshake:
    """Manages SSTP connection handshake."""
    
    def __init__(self, server: str, port: int = 443, 
                 username: str = '', password: str = ''):
        """Initialize SSTP handshake.
        
        Args:
            server: SSTP server hostname/IP
            port: Server port (default 443)
            username: Authentication username
            password: Authentication password
        """
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        
        self.sock: Optional[socket.socket] = None
        self.ssl_sock: Optional[ssl.SSLSocket] = None
    
    def connect(self) -> ssl.SSLSocket:
        """Perform full SSTP handshake.
        
        Returns:
            SSL socket with established SSTP connection
        
        Raises:
            ConnectionError: If handshake fails
        """
        logger.info(f"Connecting to SSTP server {self.server}:{self.port}")
        
        # Step 1: TCP connection
        self._tcp_connect()
        
        # Step 2: SSL/TLS handshake
        self._ssl_handshake()
        
        # Step 3: HTTP CONNECT
        self._http_connect()
        
        # Step 4: SSTP negotiation
        self._sstp_negotiation()
        
        logger.info("SSTP handshake completed successfully")
        return self.ssl_sock
    
    def _tcp_connect(self):
        """Establish TCP connection to server."""
        logger.debug(f"Establishing TCP connection to {self.server}:{self.port}")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10.0)
        self.sock.connect((self.server, self.port))
        logger.debug("TCP connection established")
    
    def _ssl_handshake(self):
        """Perform SSL/TLS handshake."""
        logger.debug("Starting SSL/TLS handshake")
        
        # Create SSL context (compatible with all platforms)
        context = ssl.create_default_context()
        # Allow self-signed certificates (for testing)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Wrap socket with SSL
        self.ssl_sock = context.wrap_socket(
            self.sock,
            server_hostname=self.server
        )
        
        logger.debug(f"SSL/TLS handshake complete. Cipher: {self.ssl_sock.cipher()}")
    
    def _http_connect(self):
        """Send HTTP CONNECT request and verify response."""
        logger.debug("Sending HTTP CONNECT request")
        
        # HTTP CONNECT request
        http_request = (
            f"CONNECT /sra_{{BA195980-CD49-458b-9E23-C84EE0ADCD75}}/ HTTP/1.1\r\n"
            f"Host: {self.server}\r\n"
            f"SSTPCORRELATIONID: {{00000000-0000-0000-0000-000000000000}}\r\n"
            f"\r\n"
        )
        
        self.ssl_sock.sendall(http_request.encode('utf-8'))
        
        # Read HTTP response
        response = b''
        while b'\r\n\r\n' not in response:
            chunk = self.ssl_sock.recv(1024)
            if not chunk:
                raise ConnectionError("Connection closed during HTTP handshake")
            response += chunk
        
        response_str = response.decode('utf-8', errors='ignore')
        logger.debug(f"HTTP response: {response_str[:100]}")
        
        # Verify HTTP 200 OK
        if 'HTTP/1.1 200' not in response_str and 'HTTP/1.0 200' not in response_str:
            raise ConnectionError(f"HTTP handshake failed: {response_str}")
        
        logger.debug("HTTP CONNECT successful")
    
    def _sstp_negotiation(self):
        """Perform SSTP protocol negotiation."""
        logger.debug("Starting SSTP negotiation")
        
        # Send CALL_CONNECT_REQUEST
        call_request = create_call_connect_request()
        self.ssl_sock.sendall(call_request)
        logger.debug("Sent CALL_CONNECT_REQUEST")
        
        # Receive CALL_CONNECT_ACK
        response = self._recv_sstp_packet()
        control = SSTPControlPacket.unpack(response.data)
        
        if control.message_type == SSTPMessageType.CALL_CONNECT_ACK:
            logger.debug("Received CALL_CONNECT_ACK")
        elif control.message_type == SSTPMessageType.CALL_CONNECT_NAK:
            raise ConnectionError("Server rejected connection (CALL_CONNECT_NAK)")
        else:
            raise ConnectionError(f"Unexpected SSTP message: {control.message_type}")
        
        # Send CALL_CONNECTED
        call_connected = create_call_connected()
        self.ssl_sock.sendall(call_connected)
        logger.debug("Sent CALL_CONNECTED")
        
        logger.debug("SSTP negotiation complete")
    
    def _recv_sstp_packet(self) -> SSTPPacket:
        """Receive and parse SSTP packet.
        
        Returns:
            Parsed SSTP packet
        """
        # Read header (4 bytes)
        header = self._recv_exact(4)
        packet = SSTPPacket.unpack(header)
        
        # Read remaining data
        remaining = packet.length - 4
        if remaining > 0:
            data = self._recv_exact(remaining)
            packet.data = data
        
        return packet
    
    def _recv_exact(self, n: int) -> bytes:
        """Receive exactly n bytes from socket.
        
        Args:
            n: Number of bytes to receive
        
        Returns:
            Received bytes
        """
        data = b''
        while len(data) < n:
            chunk = self.ssl_sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed while receiving data")
            data += chunk
        return data
    
    def close(self):
        """Close connection."""
        if self.ssl_sock:
            self.ssl_sock.close()
        if self.sock:
            self.sock.close()
        logger.info("Connection closed")
