"""
PPP Handler - Connects SSTP client with lwIP PPP stack.
"""
import logging
from typing import Optional, Callable

from lwip_bindings import LwIPWrapper

logger = logging.getLogger(__name__)


class PPPHandler:
    """Handles PPP frames between SSTP tunnel and lwIP stack."""
    
    def __init__(self, username: str, password: str):
        """Initialize PPP handler.
        
        Args:
            username: PPP authentication username
            password: PPP authentication password
        """
        self.username = username
        self.password = password
        
        # Initialize lwIP wrapper
        self.lwip = LwIPWrapper()
        
        # Callback for sending PPP frames through SSTP
        self.sstp_send_callback: Optional[Callable[[bytes], None]] = None
        
        # PPP connection state
        self.ppp_connected = False
    
    def set_sstp_send_callback(self, callback: Callable[[bytes], None]):
        """Set callback for sending PPP frames through SSTP tunnel.
        
        Args:
            callback: Function to call to send PPP frame through SSTP
        """
        self.sstp_send_callback = callback
        
        logger.debug("SSTP send callback configured")
    
    def start_ppp(self):
        """Start PPP connection with lwIP."""
        logger.info("Starting PPP connection with lwIP")
        
        # Initialize lwIP stack
        self.lwip.init_lwip()
        
        # Create PPP interface with callbacks
        self.lwip.create_ppp_interface(
            username=self.username,
            password=self.password,
            output_callback=self._on_lwip_output,
            status_callback=self._on_ppp_status_change
        )
        
        # Initiate PPP connection
        self.lwip.connect_ppp()
        
        logger.info("PPP connection started")
    
    def handle_ppp_frame_from_sstp(self, frame: bytes):
        """Handle PPP frame received from SSTP tunnel.
        
        Args:
            frame: Raw PPP frame from SSTP
        """
        logger.debug(f"Handling PPP frame from SSTP: {len(frame)} bytes")
        
        # Feed frame to lwIP PPP stack
        self.lwip.feed_ppp_frame(frame)
    
    def _on_lwip_output(self, frame: bytes):
        """Called when lwIP wants to send a PPP frame.
        
        Args:
            frame: PPP frame to send
        """
        logger.debug(f"lwIP output PPP frame: {len(frame)} bytes")
        
        if self.sstp_send_callback:
            self.sstp_send_callback(frame)
        else:
            logger.warning("No SSTP send callback set, dropping PPP frame")
    
    def _on_ppp_status_change(self, err_code: int):
        """Called when PPP status changes.
        
        Args:
            err_code: Error code (0 = success)
        """
        if err_code == 0:
            logger.info("PPP connection established successfully")
            self.ppp_connected = True
        else:
            logger.warning(f"PPP status change: err_code={err_code}")
            self.ppp_connected = False
    
    def stop_ppp(self):
        """Stop PPP connection."""
        logger.info("Stopping PPP connection")
        self.lwip.close_ppp()
        self.ppp_connected = False
