"""
PPP Handler - Connects SSTP client with lwIP PPP stack.
"""
import logging
import struct
import threading
import time
from typing import Optional, Callable

from lwip_bindings import LwIPWrapper

logger = logging.getLogger(__name__)


class HDLCHandler:
    """Handles HDLC framing/escaping for PPPoS."""
    
    @staticmethod
    def decode(data: bytes) -> bytes:
        """Unescape and unframe HDLC data to get raw PPP frame for SSTP."""
        parts = data.split(b'\x7e')
        for part in parts:
            if len(part) < 4: continue
            
            # Unescape
            unbound = bytearray()
            escaped = False
            for b in part:
                if b == 0x7d:
                    escaped = True
                elif escaped:
                    unbound.append(b ^ 0x20)
                    escaped = False
                else:
                    unbound.append(b)
            
            # Now we have [FF 03] + [PPP] + [FCS]
            res = bytes(unbound)
            # Keep FF 03 if present, as the server seems to expect/send it
            # Just strip FCS (last 2 bytes)
            if len(res) > 2:
                return res[:-2]
        return b''

    @staticmethod
    def encode(raw_ppp: bytes) -> bytes:
        """Wrap raw PPP frame into HDLC for lwIP."""
        # Ensure we have FF 03 header for lwIP's pppos
        if not raw_ppp.startswith(b'\xff\x03'):
            data = b'\xff\x03' + raw_ppp
        else:
            data = raw_ppp
        
        # Calculate FCS (CRC-CCITT)
        fcs = HDLCHandler.fcs16(data)
        fcs_final = fcs ^ 0xFFFF
        
        # Verify GOODFCS property: fcs16(data + fcs_final_le) should be 0xf0b8
        fcs_le = struct.pack('<H', fcs_final)
        good_fcs_check = HDLCHandler.fcs16(data + fcs_le)
        if good_fcs_check != 0xf0b8:
            logger.error(f"FCS self-check FAILED: 0x{good_fcs_check:04x} != 0xf0b8")
        else:
            logger.debug(f"FCS self-check OK (0xf0b8)")

        logger.debug(f"Calculated FCS for {len(data)} bytes: {fcs:04x} -> {fcs_final:04x} (le: {fcs_le.hex()})")
        data_with_fcs = data + fcs_le
        
        # Escape and Frame
        # Default ACCM for LCP is 0xFFFFFFFF (escape all 0x00-0x1F)
        out = bytearray([0x7e])
        for b in data_with_fcs:
            if b < 0x20 or b in (0x7e, 0x7d):
                out.append(0x7d)
                out.append(b ^ 0x20)
            else:
                out.append(b)
        out.append(0x7e)
        return bytes(out)

    @staticmethod
    def fcs16(data: bytes) -> int:
        """Calculate PPP FCS-16."""
        fcs = 0xFFFF
        for b in data:
            fcs = (fcs >> 8) ^ HDLCHandler.fcs_table[(fcs ^ b) & 0xff]
        return fcs

    fcs_table = [
        0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
        0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
        0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
        0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
        0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
        0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
        0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
        0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
        0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
        0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
        0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
        0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
        0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
        0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
        0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
        0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
        0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
        0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
        0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
        0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
        0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
        0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
        0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
        0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
        0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
        0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
        0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
        0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
        0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
        0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
        0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
        0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
    ]


class PPPHandler:
    """Handles PPP frames between SSTP tunnel and lwIP stack."""
    
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.lwip = LwIPWrapper()
        self.sstp_send_callback: Optional[Callable[[bytes], None]] = None
        self.on_auth_success_callback: Optional[Callable[[], None]] = None
        self.ppp_connected = False
        
        # Timer thread for lwIP
        self.timer_thread: Optional[threading.Thread] = None
        self.running = False
    
    def set_sstp_send_callback(self, callback: Callable[[bytes], None]):
        self.sstp_send_callback = callback
    
    def start_ppp(self):
        logger.info("Starting PPP connection with lwIP")
        self.lwip.init_lwip()
        self.lwip.create_ppp_interface(
            username=self.username,
            password=self.password,
            output_callback=self._on_lwip_output,
            status_callback=self._on_ppp_status_change
        )
        self.lwip.connect_ppp()
        
        # Start timer thread
        self.running = True
        self.timer_thread = threading.Thread(target=self._timer_loop, daemon=True)
        self.timer_thread.start()
        
        logger.info("PPP connection started and timer thread active")
    
    def _timer_loop(self):
        """Periodically process lwIP timers."""
        while self.running:
            self.lwip.process_timeouts()
            time.sleep(0.1)  # 100ms
            
    def handle_ppp_frame_from_sstp(self, raw_frame: bytes):
        """Handle raw PPP frame received from SSTP tunnel."""
        logger.debug(f"Handling PPP frame from SSTP ({len(raw_frame)} bytes): {raw_frame.hex()}")
        # Wrap raw frame into HDLC for lwIP
        hdlc_frame = HDLCHandler.encode(raw_frame)
        self.lwip.feed_ppp_frame(hdlc_frame)
    
    def _on_lwip_output(self, hdlc_frame: bytes):
        """Called when lwIP outputs HDLC-framed PPP data."""
        # Unwrap HDLC to get raw PPP for SSTP
        raw_frame = HDLCHandler.decode(hdlc_frame)
        if raw_frame:
            logger.debug(f"lwIP output raw PPP frame ({len(raw_frame)} bytes): {raw_frame.hex()}")
            if self.sstp_send_callback:
                self.sstp_send_callback(raw_frame)
        else:
            logger.debug(f"lwIP output HDLC frame (yielded no raw PPP): {len(hdlc_frame)} bytes")
    
    def _on_ppp_status_change(self, err_code: int):
        if err_code == 0:
            addrs = self.lwip.get_ip_addresses()
            logger.info(f"PPP connection established successfully: {addrs}")
            self.ppp_connected = True
            
            # Get MPPE keys for Crypto Binding
            send_key, recv_key = self.lwip.get_mppe_keys()
            logger.debug(f"Retrieved MPPE keys: send={send_key.hex() if send_key else 'None'}, recv={recv_key.hex() if recv_key else 'None'}")
            
            if self.on_auth_success_callback:
                # Pass keys if provided
                self.on_auth_success_callback(send_key, recv_key)
        else:
            logger.warning(f"PPP status change: err_code={err_code}")
            self.ppp_connected = False
    
    def stop_ppp(self):
        logger.info("Stopping PPP connection")
        self.running = False
        if self.timer_thread:
            self.timer_thread.join(timeout=1.0)
        self.lwip.close_ppp()
        self.ppp_connected = False
