"""
Port Binding - Expose VPN resource on local port.
Creates local TCP listener that forwards connections through SSTP tunnel.
"""
import socket
import threading
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class PortBinding:
    """TCP port binding for exposing VPN resources locally."""
    
    def __init__(self, local_port: int, target_ip: str, target_port: int):
        """Initialize port binding.
        
        Args:
            local_port: Local port to listen on
            target_ip: Target IP inside VPN
            target_port: Target port inside VPN
        """
        self.local_port = local_port
        self.target_ip = target_ip
        self.target_port = target_port
        
        self.server_sock: Optional[socket.socket] = None
        self.running = False
        self.accept_thread: Optional[threading.Thread] = None
    
    def start(self):
        """Start listening on local port."""
        logger.info(f"Starting port binding: localhost:{self.local_port} -> {self.target_ip}:{self.target_port}")
        
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(('127.0.0.1', self.local_port))
        self.server_sock.listen(5)
        
        self.running = True
        self.accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.accept_thread.start()
        
        logger.info(f"Port binding active on localhost:{self.local_port}")
    
    def _accept_loop(self):
        """Accept incoming connections."""
        logger.debug("Starting accept loop")
        
        while self.running:
            try:
                self.server_sock.settimeout(1.0)
                client_sock, addr = self.server_sock.accept()
                logger.info(f"Accepted connection from {addr}")
                
                # Handle connection in separate thread
                handler = threading.Thread(
                    target=self._handle_connection,
                    args=(client_sock,),
                    daemon=True
                )
                handler.start()
            
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting connection: {e}")
                break
        
        logger.debug("Accept loop stopped")
    
    def _handle_connection(self, client_sock: socket.socket):
        """Handle individual client connection.
        
        Args:
            client_sock: Client socket
        """
        try:
            # TODO: Create lwIP socket to target_ip:target_port
            # TODO: Relay data bidirectionally
            
            # Placeholder: echo server for testing
            logger.info(f"Handling connection (placeholder - will connect to {self.target_ip}:{self.target_port})")
            
            while True:
                data = client_sock.recv(4096)
                if not data:
                    break
                # TODO: Send through lwIP to VPN target
                # For now, just echo back
                client_sock.sendall(data)
        
        except Exception as e:
            logger.error(f"Error handling connection: {e}")
        finally:
            client_sock.close()
            logger.debug("Connection closed")
    
    def stop(self):
        """Stop port binding."""
        logger.info("Stopping port binding")
        self.running = False
        
        if self.server_sock:
            self.server_sock.close()
        
        if self.accept_thread:
            self.accept_thread.join(timeout=2.0)
        
        logger.info("Port binding stopped")
