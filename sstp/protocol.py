"""
SSTP Protocol Constants and Message Definitions.
Based on Microsoft's [MS-SSTP] specification.
"""
import struct
from enum import IntEnum


class SSTPVersion(IntEnum):
    """SSTP protocol version."""
    SSTP_VERSION_1 = 0x10


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
        # Byte 0: Version (high 4 bits) + Reserved (low 4 bits, set C bit if control)
        byte0 = (self.version << 4) | (0x01 if self.is_control else 0x00)
        # Byte 1: Reserved
        byte1 = 0x00
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
        
        version = (byte0 >> 4) & 0x0F
        is_control = bool(byte0 & 0x01)
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
            attr_len = 4 + len(attr_value)  # ID (1) + Reserved (1) + Length (2) + Value
            attr_data += struct.pack('!BBH', attr_id, 0x00, attr_len) + attr_value
        
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
            attr_id, _, attr_len = struct.unpack('!BBH', data[offset:offset+4])
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


def create_call_connected() -> bytes:
    """Create SSTP CALL_CONNECTED packet."""
    control = SSTPControlPacket(SSTPMessageType.CALL_CONNECTED)
    packet = SSTPPacket(is_control=True, data=control.pack())
    return packet.pack()


def create_echo_request() -> bytes:
    """Create SSTP ECHO_REQUEST packet."""
    control = SSTPControlPacket(SSTPMessageType.ECHO_REQUEST)
    packet = SSTPPacket(is_control=True, data=control.pack())
    return packet.pack()


def create_ppp_data_packet(ppp_frame: bytes) -> bytes:
    """Encapsulate PPP frame in SSTP data packet."""
    packet = SSTPPacket(is_control=False, data=ppp_frame)
    return packet.pack()
