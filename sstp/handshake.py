"""
SSTP Handshake Implementation - Using pyOpenSSL for Crypto Binding support.
"""
import socket
import logging
from typing import Optional, Tuple
from OpenSSL import SSL
import struct
import hmac
import hashlib

from .protocol import (
    create_call_connect_request,
    create_call_connected,
    create_crypto_binding_attribute,
    SSTPPacket,
    SSTPControlPacket,
    SSTPMessageType,
    SSTPAttributeId
)

logger = logging.getLogger(__name__)


class SSTPHandshake:
    """Manages SSTP connection handshake using pyOpenSSL."""
    
    def __init__(self, server: str, port: int = 443, 
                 username: str = '', password: str = ''):
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        
        self.sock: Optional[socket.socket] = None
        self.ssl_sock: Optional[SSL.Connection] = None
    
    def connect(self) -> SSL.Connection:
        """Perform full SSTP handshake."""
        print(f"[*] Iniciando conexión SSTP a {self.server}:{self.port}...")
        logger.info(f"Connecting to SSTP server {self.server}:{self.port}")
        
        # Step 1: TCP connection
        self._tcp_connect()
        
        # Step 2: SSL/TLS handshake
        self._ssl_handshake()
        
        # Step 3 & 4: HTTP and SSTP negotiation
        self._perform_handshake()
        
        print(f"[+] Handshake completado con éxito.")
        logger.info("SSTP handshake completed successfully")
        return self.ssl_sock

    def _tcp_connect(self):
        """Establish TCP connection."""
        logger.debug(f"Establishing TCP connection to {self.server}:{self.port}")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10.0)
        self.sock.connect((self.server, self.port))
        logger.debug("TCP connection established")

    def _ssl_handshake(self):
        """Perform SSL/TLS handshake using pyOpenSSL."""
        logger.debug("Starting SSL/TLS handshake (pyOpenSSL)")
        
        # TLS_METHOD is the modern way to support all versions
        context = SSL.Context(SSL.TLS_METHOD)
        # Disable certificate verification
        context.set_verify(SSL.VERIFY_NONE, lambda *x: True)
        
        self.ssl_sock = SSL.Connection(context, self.sock)
        self.ssl_sock.set_connect_state()
        
        # SNI can be important even for IPs if the server expects it
        sni_host = "npv.ucf.edu.cu"
        self.ssl_sock.set_tlsext_host_name(sni_host.encode('utf-8'))
        
        try:
            import select
            while True:
                try:
                    self.ssl_sock.do_handshake()
                    break
                except SSL.WantReadError:
                    select.select([self.sock], [], [], self.sock.gettimeout())
                except SSL.WantWriteError:
                    select.select([], [self.sock], [], self.sock.gettimeout())
        except SSL.Error as e:
            # Try to get more details if available
            try:
                error_details = []
                if e.args and isinstance(e.args[0], list):
                    for err in e.args[0]:
                        if isinstance(err, tuple) and len(err) >= 3:
                            error_details.append(f"{err[0]}:{err[1]}:{err[2]}")
                detail_str = " | ".join(error_details) if error_details else str(e)
            except:
                detail_str = str(e)
                
            logger.error(f"OpenSSL error during handshake: {detail_str}")
            raise ConnectionError(f"SSL handshake failed: {detail_str}")
        except Exception as e:
            logger.error(f"Unexpected error during SSL handshake: {e}")
            raise
            
        logger.debug(f"SSL/TLS handshake complete. Cipher: {self.ssl_sock.get_cipher_name()}")

    def _perform_handshake(self):
        """Perform coordinated HTTP and SSTP negotiation."""
        import uuid
        correlation_id = str(uuid.uuid4()).upper()
        
        method = "SSTP_DUPLEX_POST"
        http_request = (
            f"{method} /sra_{{BA195980-CD49-458b-9E23-C84EE0ADCD75}}/ HTTP/1.1\r\n"
            f"Host: npv.ucf.edu.cu\r\n"
            f"SSTPCORRELATIONID: {{{correlation_id}}}\r\n"
            f"Content-Length: 18446744073709551615\r\n"
            f"User-Agent: SSTP-Client/1.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"\r\n"
        )
        
        print(f"[*] Enviando petición HTTP {method}...")
        self.ssl_sock.sendall(http_request.encode('utf-8'))
        
        call_request = create_call_connect_request()
        print(f"[*] Enviando SSTP CALL_CONNECT_REQUEST...")
        self.ssl_sock.sendall(call_request)
        
        print("[*] Esperando respuesta del servidor...")
        response = b''
        while b'\r\n\r\n' not in response:
            try:
                chunk = self.ssl_sock.recv(1024)
                if not chunk:
                    raise ConnectionError("Connection closed during HTTP handshake")
                response += chunk
            except SSL.WantReadError:
                continue
        
        response_str = response.decode('utf-8', errors='ignore')
        if 'HTTP/1.1 200' not in response_str and 'HTTP/1.0 200' not in response_str:
            print(f"[-] Error: Handshake HTTP falló. Respuesta: {response_str.split('\\r\\n')[0]}")
            raise ConnectionError(f"HTTP handshake failed: {response_str}")
        
        print("[+] Túnel HTTP establecido. Negociando SSTP...")
        
        response_pkt = self._recv_sstp_packet()
        control = SSTPControlPacket.unpack(response_pkt.data)
        
        self.nonce = None
        self.hash_id = 0x01 # Default to SHA256
        if control.message_type == SSTPMessageType.CALL_CONNECT_ACK:
            print("[+] Recibido CALL_CONNECT_ACK")
            for attr_id, attr_value in control.attributes:
                if attr_id == SSTPAttributeId.CRYPTO_BINDING_REQ:
                    if len(attr_value) >= 36:
                        self.hash_id = attr_value[3]
                        self.nonce = attr_value[4:36]
                        print(f"[*] Extraído Nonce y HashID ({self.hash_id}) para Crypto Binding")
        elif control.message_type == SSTPMessageType.CALL_CONNECT_NAK:
            print("[-] Error: El servidor rechazó la conexión (CALL_CONNECT_NAK)")
            raise ConnectionError("Server rejected connection (CALL_CONNECT_NAK)")
        
        print("[+] Negociación SSTP inicial completada (esperando PPP Auth)")

    def send_call_connected(self, send_key=None, recv_key=None):
        """Send the CALL_CONNECTED message with Crypto Binding."""
        if self.nonce:
            print("[*] Calculating Crypto Binding...")
            # 1. Export keying material from TLS (Master Key MK)
            mk = self.ssl_sock.export_keying_material(b"SSTP Key Binding", 32)
            print(f"[*] TLS Master Key (MK): {mk.hex()}")

            # 2. Prepare Higher Layer Key (HLK)
            # According to MS-SSTP: HLK = Concatenate (Authenticated-Session-Key, 16 zero-padded bytes)
            # But in practice with MS-CHAPv2 it's often SendKey + RecvKey
            if send_key and recv_key:
                hlk = send_key + recv_key
                print(f"[*] Higher Layer Key (HLK) from MS-CHAPv2: {hlk.hex()}")
            else:
                hlk = b'\x00' * 32
                print("[!] No MS-CHAPv2 keys provided, using zero-filled HLK")

            # 3. Compute CMK (Compound MAC Key)
            # CMK = HMAC-SHA256(MK, HLK)
            cmk = hmac.new(mk, hlk, hashlib.sha256).digest()
            print(f"[*] Compound MAC Key (CMK): {cmk.hex()}")

            # 4. Get Certificate Hash (32 bytes SHA256)
            cert = self.ssl_sock.get_peer_certificate()
            cert_hash_hex = cert.digest('sha256').decode('ascii').replace(':', '')
            cert_hash = bytes.fromhex(cert_hash_hex)

            # 5. Prepare Full CALL_CONNECTED packet
            sstp_header = b'\x10\x01\x00\x70'
            control_header = b'\x00\x04\x00\x01'
            attr_header = b'\x01\x03\x00\x68'
            # ProtocolId 2 = SSTP_CRYPTO_BINDING_PROTOCOL_ID_IPV4? No, 1=IPv4, 2=IPv6? 
            # Actually ProtocolId 2 is often used for MS-CHAPv2 in binding.
            attr_value_prefix = b'\x00\x00\x00\x02' + self.nonce + cert_hash
            full_packet_with_zeros = sstp_header + control_header + attr_header + attr_value_prefix + (b'\x00' * 32)

            # 6. Compute Compound MAC
            mac = hmac.new(cmk, full_packet_with_zeros, hashlib.sha256).digest()

            # 7. Final CALL_CONNECTED packet
            call_connected = sstp_header + control_header + attr_header + attr_value_prefix + mac
            print(f"[*] Sending CALL_CONNECTED with Crypto Binding (MAC: {mac.hex()})...")
            self.ssl_sock.sendall(call_connected)
        else:
            call_connected = create_call_connected()
            print("[*] Sending CALL_CONNECTED (without Crypto Binding)...")
            self.ssl_sock.sendall(call_connected)

        print("[+] CALL_CONNECTED sent successfully.")

    def _recv_sstp_packet(self) -> SSTPPacket:
        header = self._recv_exact(4)
        packet = SSTPPacket.unpack(header)
        remaining = packet.length - 4
        if remaining > 0:
            packet.data = self._recv_exact(remaining)
        return packet
    
    def _recv_exact(self, n: int) -> bytes:
        data = b''
        while len(data) < n:
            try:
                chunk = self.ssl_sock.recv(n - len(data))
                if not chunk:
                    raise ConnectionError("Connection closed")
                data += chunk
            except SSL.WantReadError:
                continue
        return data
    
    def close(self):
        if self.ssl_sock:
            try:
                self.ssl_sock.shutdown()
            except:
                pass
            self.ssl_sock.close()
        if self.sock:
            self.sock.close()
        logger.info("Connection closed")
