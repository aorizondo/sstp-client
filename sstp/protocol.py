"""
SSTP Protocol Constants and Message Definitions.
Based on Microsoft's [MS-SSTP] specification.
"""
import struct
from enum import IntEnum
from typing import Optional


class SSTPVersion(IntEnum):
    """SSTP protocol version."""
    SSTP_VERSION_1 = 0x01


class SSTPMessageType(IntEnum):
    """SSTP control message types."""
    CALL_CONNECT_REQUEST = 0x0001
    CALL_CONNECT_ACK = 0x0002
    CALL_CONNECT_NAK = 0x0003
    CALL_CONNECTED = 0x0004
    CALL_ABORT = 0x0005
    CALL_DISCONNECT = 0x0006
    CALL_DISCONNECT_ACK = 0x0007
    ECHO_REQUEST = 0x0008
    ECHO_RESPONSE = 0x0009


class SSTPAttributeId(IntEnum):
    """SSTP attribute IDs."""
    ENCAPSULATED_PROTOCOL_ID = 0x01
    STATUS_INFO = 0x02
    CRYPTO_BINDING = 0x03
    CRYPTO_BINDING_REQ = 0x04


class SSTPEncapsulatedProtocol(IntEnum):
    """Encapsulated protocol types."""
    PPP = 0x0001


class SSTPPacket:
    """SSTP packet structure."""
    
    HEADER_SIZE = 4  # Version (1) + Reserved (1) + Length (2)
    
    def __init__(self, version: int = SSTPVersion.SSTP_VERSION_1, 
                 is_control: bool = True, length: int = 0, data: bytes = b''):
        self.version = version
        self.is_control = is_control
        self.length = length
        self.data = data
    
    def pack(self) -> bytes:
        """Pack SSTP packet to bytes."""
        # Many implementations (e.g. sstp-client) use 0x10 for the first byte 
        # for Version 1, and 0x01 for the second byte if it's a control packet.
        
        byte0 = 0x10
        byte1 = 0x01 if self.is_control else 0x00
        
        # Bytes 2-3: Length (big endian)
        length = self.HEADER_SIZE + len(self.data)
        
        header = struct.pack('!BBH', byte0, byte1, length)
        return header + self.data
    
    @classmethod
    def unpack(cls, data: bytes) -> 'SSTPPacket':
        """Unpack SSTP packet from bytes."""
        if len(data) < cls.HEADER_SIZE:
            raise ValueError(f"Packet too short: {len(data)} bytes")
        
        byte0, byte1, length = struct.unpack('!BBH', data[:cls.HEADER_SIZE])
        
        # Version is usually in high nibble of byte0
        version = (byte0 >> 4) & 0x0F
        is_control = bool(byte1 & 0x01)
        packet_data = data[cls.HEADER_SIZE:length]
        
        return cls(version, is_control, length, packet_data)


class SSTPControlPacket:
    """SSTP control packet with message type and attributes."""
    
    def __init__(self, message_type: SSTPMessageType, attributes: list = None):
        self.message_type = message_type
        self.attributes = attributes or []
    
    def pack(self) -> bytes:
        """Pack control packet to bytes."""
        # Message Type (2 bytes) + Num Attributes (2 bytes)
        header = struct.pack('!HH', self.message_type, len(self.attributes))
        
        # Pack attributes
        attr_data = b''
        for attr_id, attr_value in self.attributes:
            attr_len = 4 + len(attr_value)
            # Byte 0: Reserved (7 bits) + M (1 bit). M=1 means Mandatory.
            # Byte 1: Attribute ID (1 byte)
            # Byte 2-3: Length (2 bytes)
            attr_data += struct.pack('!BBH', 0x01, attr_id, attr_len) + attr_value
        
        return header + attr_data
    
    @classmethod
    def unpack(cls, data: bytes) -> 'SSTPControlPacket':
        """Unpack control packet from bytes."""
        if len(data) < 4:
            raise ValueError("Control packet too short")
        
        message_type, num_attrs = struct.unpack('!HH', data[:4])
        
        # Parse attributes
        attributes = []
        offset = 4
        for _ in range(num_attrs):
            if offset + 4 > len(data):
                break
            # Byte 0: Reserved/M, Byte 1: Attr ID, Byte 2-3: Length
            _, attr_id, attr_len = struct.unpack('!BBH', data[offset:offset+4])
            attr_value = data[offset+4:offset+attr_len]
            attributes.append((attr_id, attr_value))
            offset += attr_len
        
        return cls(SSTPMessageType(message_type), attributes)


def create_call_connect_request() -> bytes:
    """Create SSTP CALL_CONNECT_REQUEST packet."""
    # Add ENCAPSULATED_PROTOCOL_ID attribute (PPP)
    protocol_value = struct.pack('!H', SSTPEncapsulatedProtocol.PPP)
    
    control = SSTPControlPacket(
        SSTPMessageType.CALL_CONNECT_REQUEST,
        [(SSTPAttributeId.ENCAPSULATED_PROTOCOL_ID, protocol_value)]
    )
    
    packet = SSTPPacket(is_control=True, data=control.pack())
    return packet.pack()


def create_call_connected(attributes: Optional[list] = None) -> bytes:
    """Create SSTP CALL_CONNECTED packet."""
    control = SSTPControlPacket(
        SSTPMessageType.CALL_CONNECTED,
        attributes=attributes or []
    )
    packet = SSTPPacket(is_control=True, data=control.pack())
    return packet.pack()


def create_crypto_binding_attribute(nonce: bytes, cmk: bytes) -> bytes:
    """Create CRYPTO_BINDING attribute value.
    
    Args:
        nonce: 32-byte nonce from CRYPTO_BINDING_REQ
        cmk: Computed Compound MAC Key (HMAC-SHA256)
        
    Returns:
        Packed attribute value (excluding attribute header)
    """
    # [MS-SSTP] Section 2.2.6
    # Reserved (3 bytes) + Hash Protocol ID (1 byte) + Nonce (32 bytes) + Cert Hash (32 bytes) + MAC (32 bytes)
    # Hash Protocol ID: 0x01 = SHA256
    
    cert_hash = b'\x00' * 32
    
    # Pack Reserved (3) + Hash Protocol ID (1)
    value = b'\x00\x00\x00\x01'
    value += nonce
    value += cert_hash
    value += cmk
    
    return value


def create_echo_request() -> bytes:
    """Create SSTP ECHO_REQUEST packet."""
    control = SSTPControlPacket(SSTPMessageType.ECHO_REQUEST)
    packet = SSTPPacket(is_control=True, data=control.pack())
    return packet.pack()


def create_ppp_data_packet(ppp_frame: bytes) -> bytes:
    """Encapsulate PPP frame in SSTP data packet."""
    packet = SSTPPacket(is_control=False, data=ppp_frame)
    return packet.pack()
