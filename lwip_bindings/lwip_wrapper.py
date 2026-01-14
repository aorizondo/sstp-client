"""
lwIP Python bindings using ctypes - Complete implementation.
Provides PPP support for SSTP tunnel.
"""
import ctypes
import os
from pathlib import Path
from typing import Optional, Callable
import logging

logger = logging.getLogger(__name__)

# Find lwIP shared library
LWIP_LIB_PATH = Path(__file__).parent.parent / "py-lwip" / "lwip_lib" / "build" / "liblwip.so"


# C structure definitions
class ip4_addr_t(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_uint32)]


class netif(ctypes.Structure):
    pass  # Forward declaration


# Callback types
PPP_LINK_STATUS_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p)
PPPOS_OUTPUT_CB = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p)


class LwIPWrapper:
    """Complete lwIP wrapper with PPP support."""
    
    def __init__(self, lib_path: Optional[str] = None):
        """Initialize lwIP library.
        
        Args:
            lib_path: Path to liblwip.so. If None, uses default location.
        """
        if lib_path is None:
            lib_path = str(LWIP_LIB_PATH)
        
        if not os.path.exists(lib_path):
            raise FileNotFoundError(
                f"lwIP library not found at {lib_path}. "
                "Run 'make lwip_lib' in py-lwip directory first."
            )
        
        logger.info(f"Loading lwIP library from {lib_path}")
        self.lib = ctypes.CDLL(lib_path)
        self._setup_functions()
        
        self.ppp_pcb = None
        self.netif_ptr = None
        self.output_callback = None
        self._output_cb_ref = None  # Keep reference to prevent GC
        self._status_cb_ref = None
    
    def _setup_functions(self):
        """Setup function signatures for lwIP PPP functions."""
        
        # lwIP initialization
        try:
            self.lib.lwip_init.argtypes = []
            self.lib.lwip_init.restype = None
        except AttributeError:
            logger.warning("lwip_init not found in library")
        
        # PPPoS functions
        try:
            # ppp_pcb *pppos_create(struct netif *pppif, pppos_output_cb_fn output_cb,
            #                       ppp_link_status_cb_fn link_status_cb, void *ctx_cb)
            self.lib.pppos_create.argtypes = [
                ctypes.POINTER(netif),
                PPPOS_OUTPUT_CB,
                PPP_LINK_STATUS_CB,
                ctypes.c_void_p
            ]
            self.lib.pppos_create.restype = ctypes.c_void_p
            
            # void pppos_input(ppp_pcb *ppp, const void* data, int len)
            self.lib.pppos_input.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_int
            ]
            self.lib.pppos_input.restype = None
            
            # err_t ppp_set_auth(ppp_pcb *pcb, u8_t authtype, const char *user, const char *passwd)
            self.lib.ppp_set_auth.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint8,
                ctypes.c_char_p,
                ctypes.c_char_p
            ]
            self.lib.ppp_set_auth.restype = ctypes.c_int
            
            # err_t ppp_connect(ppp_pcb *pcb, u16_t holdoff)
            self.lib.ppp_connect.argtypes = [ctypes.c_void_p, ctypes.c_uint16]
            self.lib.ppp_connect.restype = ctypes.c_int
            
            # err_t ppp_close(ppp_pcb *pcb, u8_t nocarrier)
            self.lib.ppp_close.argtypes = [ctypes.c_void_p, ctypes.c_uint8]
            self.lib.ppp_close.restype = ctypes.c_int
            
            logger.debug("lwIP PPP functions loaded successfully")
        except AttributeError as e:
            logger.warning(f"Some PPP functions not found: {e}")
    
    def init_lwip(self):
        """Initialize lwIP stack."""
        try:
            self.lib.lwip_init()
            logger.info("lwIP stack initialized")
        except AttributeError:
            logger.warning("lwip_init not available, skipping")
    
    def create_ppp_interface(self, username: str, password: str, 
                            output_callback: Callable[[bytes], None],
                            status_callback: Optional[Callable[[int], None]] = None):
        """Create PPP interface.
        
        Args:
            username: PPP authentication username
            password: PPP authentication password
            output_callback: Callback for sending PPP frames
            status_callback: Optional callback for link status changes
        """
        self.output_callback = output_callback
        
        # Create output callback wrapper
        def output_cb_wrapper(pcb, data, length, ctx):
            try:
                # Convert C data to Python bytes
                data_bytes = ctypes.string_at(data, length)
                if self.output_callback:
                    self.output_callback(data_bytes)
                return length
            except Exception as e:
                logger.error(f"Error in output callback: {e}")
                return 0
        
        # Create status callback wrapper
        def status_cb_wrapper(pcb, err_code, ctx):
            try:
                logger.info(f"PPP status changed: err_code={err_code}")
                if status_callback:
                    status_callback(err_code)
            except Exception as e:
                logger.error(f"Error in status callback: {e}")
        
        # Keep references to prevent garbage collection
        self._output_cb_ref = PPPOS_OUTPUT_CB(output_cb_wrapper)
        self._status_cb_ref = PPP_LINK_STATUS_CB(status_cb_wrapper)
        
        # Allocate netif structure
        self.netif_ptr = ctypes.pointer(netif())
        
        try:
            # Create PPPoS interface
            self.ppp_pcb = self.lib.pppos_create(
                self.netif_ptr,
                self._output_cb_ref,
                self._status_cb_ref,
                None
            )
            
            if not self.ppp_pcb:
                raise RuntimeError("Failed to create PPP interface")
            
            logger.info("PPP interface created successfully")
            
            # Set authentication (PPPAUTHTYPE_ANY = 0xff)
            auth_result = self.lib.ppp_set_auth(
                self.ppp_pcb,
                0xff,  # PPPAUTHTYPE_ANY
                username.encode('utf-8'),
                password.encode('utf-8')
            )
            
            if auth_result != 0:
                logger.warning(f"ppp_set_auth returned {auth_result}")
            else:
                logger.info(f"PPP authentication configured for user: {username}")
            
        except Exception as e:
            logger.error(f"Failed to create PPP interface: {e}")
            raise
    
    def connect_ppp(self):
        """Initiate PPP connection."""
        if not self.ppp_pcb:
            raise RuntimeError("PPP interface not created")
        
        result = self.lib.ppp_connect(self.ppp_pcb, 0)
        if result != 0:
            logger.warning(f"ppp_connect returned {result}")
        else:
            logger.info("PPP connection initiated")
    
    def feed_ppp_frame(self, frame: bytes):
        """Feed PPP frame into lwIP stack.
        
        Args:
            frame: Raw PPP frame bytes
        """
        if not self.ppp_pcb:
            logger.warning("PPP interface not created, dropping frame")
            return
        
        try:
            # Create C buffer from Python bytes
            data_buf = ctypes.create_string_buffer(frame)
            self.lib.pppos_input(self.ppp_pcb, data_buf, len(frame))
            logger.debug(f"Fed PPP frame to lwIP: {len(frame)} bytes")
        except Exception as e:
            logger.error(f"Error feeding PPP frame: {e}")
    
    def close_ppp(self):
        """Close PPP connection."""
        if self.ppp_pcb:
            self.lib.ppp_close(self.ppp_pcb, 0)
            logger.info("PPP connection closed")
