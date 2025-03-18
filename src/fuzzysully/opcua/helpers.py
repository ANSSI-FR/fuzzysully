"""OPCUA messages helpers

This module provide some helpers used in message structure
definition.
"""

import math
import random
import string
import struct
from calendar import timegm
from datetime import datetime
from struct import pack
from typing import Union
from uuid import UUID
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from fuzzowski import s_block, s_dword, s_string, s_size, s_group, s_static, s_byte
from . import OpcuaGlobalParams
from ..helpers import s_random

# OPC 1000-3 - 8.29
NODE_CLASS = ([pack("<I", i) for i in [0, 1, 2, 4, 8, 16, 32, 64, 128]] +
              [pack("<I", 256)])

# OPC 1000-4 - 5.5.2.2
REQUEST_TYPE = [b"\x00\x00\x00\x00", b"\x01\x00\x00\x00"] + [b"\xFF\xFF\xFF\xFF"]

# OPC 1000-4 - 7.4
APPLICATION_TYPE = [pack("<I", i) for i in range(4)] + [pack("<I", 4)]

# OPC 1000-4 - 7.5
BROWSE_DIRECTION = [pack("<I", i) for i in range(4)] + [pack("<I", 4)]

# OPC 1000-4 - 7.20
SECURITY_MODE = [pack("<I", i) for i in range(4)] + [pack("<I", 4)]

# OPC 1000-4 - 7.23
MONITORING_MODE = [pack("<I", i) for i in range(3)] + [pack("<I", 3)]

# OPC 1000-4 - 7.40
TIMESTAMP_TO_RETURN = [pack("<I", i) for i in range(5)] + [pack("<I", 5)]

# OPC 1000-6 - 5.2.2.1
BOOLEAN = [b"\x00", b"\x01"] + [b"\xFF\xFF"]

# OPC 1000-6 - A.1
ATTRIBUTE_ID = [pack("<I", i) for i in range(1, 28)] + [pack("<I", 42)]

# Namespace index
NAMESPACE_INDEX_1 = [
    b"\x00",
    b"\x00",
    b"\x00",
    b"\x01",
    b"\x01",
    b"\x01",
    b"\x02",
    b"\x02",
    b"\x02",
    b"\x03",
    b"\x04",
    b"\x04",
]
NAMESPACE_INDEX_2 = [
    b"\x00\x00",
    b"\x00\x00",
    b"\x00\x00",
    b"\x01\x00",
    b"\x01\x00",
    b"\x01\x00",
    b"\x01\x00",
    b"\x02\x00",
    b"\x02\x00",
    b"\x02\x00",
    b"\x03\x00",
    b"\x04\x00",
    b"\x04\x00",
]

# Encoding mask (binary or xml)
ENCODING_MASK = [b"\x00", b"\x01", b"\x02"] + [b"\xFF"]

# Mutations RANGE to decrease number of possibilities
BYTE_RANGE = [pack("B", i) for i in range(0, 0xFF, 10)] + [b"\xff"]
WORD_RANGE = [pack("<H", i) for i in range(0, 0xFFFF, 1000)] + [b"\xff\xff"]
DWORD_RANGE = [pack("<I", i) for i in range(0, 0xFFFFFFFF, 10000000)] + [
    b"\xff\xff\xff\xff"
]
QWORD_RANGE = [
    pack("<Q", i) for i in range(0, 0xFFFFFFFFFFFFFFFF, 10000000000000000)
] + [b"\xff\xff\xff\xff\xff\xff\xff\xff"]

# PrivateKeyFormat possibilities
PRIVATE_KEY_FORMAT = [b"PFX", b"PEM", b"DEADBEEF", b""]

HUNDREDS_OF_NANOSECONDS = 10000000
EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970, as MS file time


def get_weird_opc_timestamp() -> int:
    """Generates a weird OPC timestamp."""
    now = datetime.now()
    ft = EPOCH_AS_FILETIME + (timegm(now.timetuple()) * HUNDREDS_OF_NANOSECONDS)
    return ft + (now.microsecond * 10)


def generate_node_id(_node_id_type: int = None):
    """
    Generates node id.

    OPC 1000-6 - 5.2.2.9
    """
    node_id = bytearray()
    if _node_id_type is None:
        node_id_type = random.randrange(6)
    else:
        node_id_type = _node_id_type
    node_id += pack("<B", node_id_type)
    if node_id_type == 0:  # Two Byte, default namespace = 0
        identifier = random.randbytes(1)
        node_id += identifier
    elif node_id_type == 1:  # Four Byte
        namespace_index = random.choice(NAMESPACE_INDEX_1)
        identifier = random.randbytes(2)
        node_id += namespace_index
        node_id += identifier
    elif node_id_type == 2:  # Numeric
        namespace_index = random.choice(NAMESPACE_INDEX_2)
        identifier = random.randbytes(4)
        node_id += namespace_index
        node_id += identifier
    elif node_id_type == 3:  # String
        namespace_index = random.choice(NAMESPACE_INDEX_2)
        node_id += namespace_index
        possible_ranges = list(range(25))
        possible_ranges.append(-1)
        str_size = random.choice(possible_ranges)
        node_id += pack("<i", str_size)
        if str_size != -1:
            result_str = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=str_size)
            )
            node_id += bytearray(result_str.encode("utf-8"))
    elif node_id_type == 4:  # GUID
        namespace_index = random.choice(NAMESPACE_INDEX_2)
        node_id += namespace_index
        guid = random.randbytes(16)
        node_id += guid
    elif node_id_type == 5:  # ByteString
        namespace_index = random.choice(NAMESPACE_INDEX_2)
        node_id += namespace_index
        possible_ranges = list(range(25))
        possible_ranges.append(-1)
        bytes_size = random.choice(possible_ranges)
        node_id += pack("<i", bytes_size)
        if bytes_size != -1:
            res_bytes = random.randbytes(bytes_size)
            node_id += res_bytes

    if node_id is None or node_id == b"":
        raise AttributeError("node id is null!")

    return bytes(node_id)


# NODE_IDS is a list of 20 times each type of node_id_type
NODE_IDS = (
    [
        b"\x00\x0b",
        b"\x00E",
        b"\x00\x94",
        b"\x00\xbb",
        b"\x00\xed",
        b"\x00\xc3",
        b"\x00)",
        b"\x00\xc3",
        b"\x00\x17",
        b"\x00\xef",
        b"\x00\xae",
        b"\x00\xd7",
        b"\x00r",
        b"\x00\xb9",
        b"\x00$",
        b"\x00\x0b",
        b"\x00`",
        b"\x00\x0c",
        b"\x00R",
        b"\x00\x83",
    ]
    + [
        b"\x01\x02|$",
        b"\x01\x00\xdb\x9d",
        b"\x01\x02L\x81",
        b"\x01\x02\x98k",
        b"\x01\x02w\xa9",
        b"\x01\x00\x12\x08",
        b"\x01\x04\xf3\xbe",
        b"\x01\x04@\x00",
        b"\x01\x03\x0f\xe4",
        b'\x01\x02"\xed',
        b"\x01\x02\xdf\xa5",
        b"\x01\x03\x05\x8e",
        b"\x01\x03\x93\xe4",
        b"\x01\x04\x81J",
        b"\x01\x00q\xe5",
        b"\x01\x01\x10\x9c",
        b"\x01\x01\xb0\x9f",
        b"\x01\x04\x9f\x9e",
        b"\x01\x01\x03\xc6",
        b"\x01\x02]\xa5",
    ]
    + [
        b"\x02\x01\x00*bD\x8d",
        b"\x02\x02\x00H\xb6)\xc4",
        b"\x02\x02\x00\x1a\xa6\x1eu",
        b"\x02\x01\x00\xde\xd6\x14\x83",
        b"\x02\x04\x00O\x80j\xbb",
        b"\x02\x02\x00\xdb\xb7\x06&",
        b"\x02\x01\x00\xa04\xde\xc7",
        b"\x02\x01\x00L\xe7\xf6\xb0",
        b"\x02\x02\x00\x1e'\x97E",
        b"\x02\x00\x00\xbbQ\x1f\x1f",
        b"\x02\x04\x00W\xa3Z\xc7",
        b"\x02\x01\x00e\x84\x0eW",
        b"\x02\x02\x00\xfb\x8eN\x0f",
        b"\x02\x00\x00\xe9\xc7n#",
        b"\x02\x04\x00\xfd\xdd\x13\xd1",
        b"\x02\x00\x00Ki\x15\xc1",
        b"\x02\x04\x00\xfb\x1a(\x8f",
        b"\x02\x02\x00\xd1\xca)$",
        b"\x02\x02\x00\xc7\xc9dR",
        b"\x02\x00\x00CQ\x0c\xc5",
    ]
    + [
        b"\x03\x01\x00\x11\x00\x00\x00BJMW709QAXULW7OQD",
        b"\x03\x02\x00\x0b\x00\x00\x004TE1PIXN4ZO",
        b"\x03\x00\x00\x02\x00\x00\x00YO",
        b"\x03\x04\x00\x02\x00\x00\x005E",
        b"\x03\x02\x00\x10\x00\x00\x00WC9SAYE61VKFK4RU",
        b"\x03\x04\x00\x18\x00\x00\x00JJNVS0VG5P5NGXZY7LOLKW7C",
        b"\x03\x02\x00\x00\x00\x00\x00",
        b"\x03\x02\x00\x01\x00\x00\x00R",
        b"\x03\x02\x00\x13\x00\x00\x00GONJJLKRQGBR9XQ9O4O",
        b"\x03\x01\x00\x00\x00\x00\x00",
        b"\x03\x01\x00\x0f\x00\x00\x00D46FPL4HJRYR6XA",
        b"\x03\x00\x00\x0f\x00\x00\x001SSQRD4FFJRQ8TJ",
        b"\x03\x01\x00\x01\x00\x00\x00G",
        b"\x03\x00\x00\x12\x00\x00\x00ULQ16I9ZUNVMXIYZ2I",
        b"\x03\x02\x00\x0f\x00\x00\x00D4A84GIF39OM26T",
        b"\x03\x02\x00\x11\x00\x00\x00TGWLF685RDLX7L4C0",
        b"\x03\x02\x00\x14\x00\x00\x00CDB874RDS8CYYYCT6FTY",
        b"\x03\x04\x00\x14\x00\x00\x008JJMLK3KTPHW4YSAS4I7",
        b"\x03\x03\x00\x11\x00\x00\x00OMKUCJR928W75CTC6",
        b"\x03\x02\x00\x02\x00\x00\x00GI",
    ]
    + [
        b"\x04\x01\x00\x9c1\x08\xff\xc0\xa7C\x81b\xf3\xde\x90\xa2'\x82S",
        b"\x04\x02\x00\xab\xda=\xc4\x00\xa1o;m\x14\xa4{\xfc\x90<]",
        b"\x04\x01\x00)O\xc3\xa7\x193\x134\x93\xe5\x9c\x9f\x9b\x06C\xfa",
        b"\x04\x01\x00\x9b$w\x9akX\xae\xc8\xb8\xf3\xe8\xfe\x959\xdc\x04",
        b"\x04\x02\x00\x8d\xb6\x04\x9d\xb6I\x9c\xe1DeUnqD\\J",
        b"\x04\x02\x00\xa9U\x14V\xa7\xe8?\xc0\xdf\xb9\x1a~\xab\x8d4`",
        b'\x04\x02\x00eX\x9c\xf5Y"\xc2-E\xa5\xac1\x95I\x94,',
        b"\x04\x00\x00\xda\x9e\xbc\xdb@\xd4R\x92w\xa9\xe0G\xe4\xc1+y",
        b"\x04\x02\x00 \x9eU\xe6\x08h\xddl\x04\x9c\x9e\xb2\x1e3\xfb\xd6",
        b"\x04\x01\x00\xa3\xb5{3D\x17!&\xa0J\x13\xeb\xfbmJB",
        b'\x04\x02\x00\xe2o\xe0\r\xb5\xef`\x1a"\x01jN~\x96\x97E',
        b"\x04\x01\x00L\x8f.\x98#\xa8\x10\x16\x0e\xaf\x1b\x1d\xa9\xba\xfa\xfb",
        b"\x04\x02\x00\x98\xe8\xc8C*\x99\x88\xbb[J+\x88a\xc5\r\xd3",
        b"\x04\x02\x00\x1a+Uc\xd5W\xac\xba\x0e\x7f\xd9kI0\xe8Z",
        b"\x04\x01\x00\xb8\x13\xf2\xe8\xf1\xcd\x92\x05Y\xaaD\t@J\xfch",
        b"\x04\x04\x00\x89\x81K1E\nt\x11\xeb\xd8\xbc\xb9~\xc2\x03[",
        b"\x04\x04\x008\xc4\xa3\x8c\x88y\xd8\x92\xa3\xdb\x14{\x8e\x975\xe9",
        b"\x04\x01\x00]'\xfeg/\xfbS[\x06\x8c+\xac\xe7}\xcc\xf8",
        b"\x04\x00\x00M\xe4%*\xc1\xb1u)N\xbdD\xced\x85\xb2Q",
        b"\x04\x04\x00W\x1d`\\\xeb\xd6ir\xfa\xba\x9d/+4\x8ex",
    ]
    + [
        b"\x05\x02\x00\x05\x00\x00\x00\xe1\xf1\x16KI",
        b"\x05\x04\x00\x17\x00\x00\x00\xac`.?\x8aw\x02\xad\x92\x94\x942\x1eQF\x01\x8d\x9e\xa3&\xab\xbe\x1d",
        b"\x05\x00\x00\x16\x00\x00\x00\xd8\xe9\xc1\x1f\xe4E\xf6x\xb3\\\xb1\x1f\xce\x82\xe4'{\xcaz>\x91\xf4",
        b"\x05\x02\x00\x01\x00\x00\x00\x95",
        b"\x05\x02\x00\t\x00\x00\x00\xc0\x05\x95\xdcA[\x0e\xba\xc2",
        b"\x05\x00\x00\x0f\x00\x00\x00g-\xf1\\Y\xcf\x85D\x06\xa8B\xe1\xb1%\x11",
        b"\x05\x00\x00\x00\x00\x00\x00",
        b"\x05\x02\x00\x16\x00\x00\x00\xebQ5Y0\xce\xc8\xe4(\x8a\x9b-\xe7\x8e9H\xceV\xd6\x86a\xe1",
        b"\x05\x01\x00\x07\x00\x00\x00c\xe6f\x85|\x85\x82",
        b"\x05\x01\x00\x15\x00\x00\x00\xe6\xf6?\x93]`\xba\x9c\x00\x10\x18\xfd\xf8E[\xfa\xbb\xfaX\x89\x08",
        b"\x05\x01\x00\x15\x00\x00\x00 \xe7\xf9!\x14\x95X\x93yF\x8a\x8f\xa1pQo\xaeWA\x185",
        b"\x05\x03\x00\t\x00\x00\x00Zf\x17\xb3\xf5q\xad\xe3\xba",
        b"\x05\x00\x00\x17\x00\x00\x00\xd9\xb4\x1b\xa1\xee\x02-\xab\r&\xf0yja\x18\x8a\xcd\xe3\xa4\xf4?\x9b\x89",
        b"\x05\x00\x00\x18\x00\x00\x00\xaf\x7f\xd6\x8f\x7f\x0b7\xeb\xd4W\xdd\x11`\xdd*\xe1\xc74\x17\x05\xdat\x04&",
        b"\x05\x02\x00\x03\x00\x00\x008\xac\xa3",
        b"\x05\x04\x00\x0c\x00\x00\x00h]\\7\xd8\xc9HILJ\x95\x9d",
        b"\x05\x01\x00\x01\x00\x00\x00\xf0",
        b"\x05\x01\x00\x0e\x00\x00\x00\xc7V\x0f\x9d\x02<\x1b\xaa\xf5\xb0z\x04\xf8+",
        b"\x05\x00\x00\x0b\x00\x00\x00\xb4\xb7\xb7\xa9\xa2\xa2\xfd\xb3&9\x89",
        b"\x05\x01\x00\x01\x00\x00\x00v",
    ]
)


def nodeid_guid(namespace: int = 0, guid: Union[str, UUID] = None) -> bytes:
    """Create a NodeId referencing a GUID as described in OPC 10000-6 Section
    5.2.2.9.
    """
    if isinstance(guid, str):
        guid = UUID(guid)
    return struct.pack("<BH", 0x04, namespace) + uuid_to_opcua_guid(guid)


def nodeid_numeric(namespace: int = 0, number: int = 0) -> bytes:
    """Create a NodeId referencing a numeric ID as described in OPC 10000-6
    Section 5.2.2.9.
    """
    # Build numeric node Id
    if number < 0x10000:
        nodeid_ = struct.pack("<BH", 0x00, namespace) + struct.pack("<H", id)
    elif number < 0x100000000:
        nodeid_ = struct.pack("<BH", 0x01, namespace) + struct.pack("<I", id)
    else:
        nodeid_ = struct.pack("<BH", 0x02, namespace) + number.to_bytes(
            math.ceil(number.bit_length() / 8)
        )

    # Return generated node id
    return nodeid_


def nodeid_string(namespace: int = 0, value: bytes = b"") -> bytes:
    """Create a NodeId referencing a string as described in OPC 10000-6
    Section 5.2.2.9.
    """
    if len(value) > 0:
        return struct.pack("<BHI", 0x03, namespace, len(value)) + value
    return struct.pack("<BHI", 0x03, namespace, 0xFFFFFFFF)


def nodeid_bytestring(namespace: int = 0, value: bytes = b"") -> bytes:
    """Create a NodeId referencing a byte string as described in OPC 10000-6
    Section 5.2.2.9.
    """
    if len(value) > 0:
        return struct.pack("<BHI", 0x05, namespace, len(value)) + value
    return struct.pack("<BHI", 0x05, namespace, 0xFFFFFFFF)


def qualified_name_common_block(name: str, fuzzable: bool = True):
    """
    Generates a Qualified name block.

    OPC 1000-6 - 5.2.2.13
    """
    with s_block(name):
        s_group(value=b"\x00\x00", values=NAMESPACE_INDEX_2, name="namespace_index")
        opcua_bytes(value=b"\xFF\xFF\xFF\xFF", name="name", to_fuzz=fuzzable)


def attribute_id():
    """
    Generates an Attribute id.

    OPC 1000-6 - A.1
    """
    s_group(value=b"\x0d\x00\x00\x00", values=ATTRIBUTE_ID, name="attribute_id")


def s_common_msg_header_block():
    """
    Defines the block 'c-header' corresponding to a message header

    OPC 1000-6 section 6.7.2.3
    """
    with s_block("c-header"):
        # We use a 'MSG' message type (a secured Message)
        s_string(b"MSG", name="MSG magic", fuzzable=False)
        # Message is not fragmented
        s_string(b"F", name="Chunk type", fuzzable=False)
        # Message size = size of message body + size of header (8)
        s_size("c-body", offset=8, name="body size", fuzzable=False)


def s_type_id(value: int):
    """Wrapper to declare a type id (value)"""
    s_string(b"\x01\x00" + struct.pack("<H", value), name="Type id", fuzzable=False)


def s_symmetric_chan_security_header():
    """Defined in OPC 1000-6"""
    # Secure Channel ID from Message Header
    s_dword(0, name="sc_id", fuzzable=False)  # overwritten by callback
    # Token ID from Symmetric Security Header as defined in 6.7.2.3.
    s_dword(4, name="sc_token", fuzzable=False)  # overwritten by callback
    # Sequence Header as defined in 6.7.2.4.
    s_dword(2, name="seq_num", fuzzable=False)  # overwritten by callback
    s_dword(2, name="req_id", fuzzable=False)  # overwritten by callback


def s_request_header(token_is_null: bool = False, timestamp: int = 0):
    """Request Header (See OPC 10000-6 section 6.7.4 and OPC 10000-4
    section 5.12.3.2 and section 7.33 defining the RequestHeader)
    """
    if token_is_null:
        # - an authentication token (set to *null*)
        s_string(b"\x00\x00", name="Authentication Token", fuzzable=False)
    else:
        # AuthenticationToken attribute_id (0x02 -> arbitrary length)
        s_string(b"\x02", name="EncodingMask", fuzzable=False)
        # Hardcoded here but can be taken from CreateSessionResponse
        s_string(b"\x00\x00", name="namespace idx", fuzzable=False)
        # Numeric Identifier
        s_dword(0, name="id_num", fuzzable=False)  # overwritten by callback

    # - a 64-bit timestamp (UtcTime)
    s_group(
        value=pack("<Q", timestamp),
        values=QWORD_RANGE,
        name="time_stamp",
    )

    # - a request handle (unique per request)
    s_dword(1, name="req_hdl", fuzzable=False)  # overwritten by callback

    # - a returnDiagnostics value (UInt32), set to 0 for no diagnostics
    s_group(value=pack("<I", 0), values=DWORD_RANGE, name="Return_diagnostics")

    # - an auditEntryId (String), defined to null string (length = -1)
    opcua_bytes(value=b"\xFF\xFF\xFF\xFF", name="AuditEntryID")

    # - a Timeout hint used by server to cancel long-running operations
    s_group(value=pack("<I", 10000), values=DWORD_RANGE, name="Timeout_hint")

    # - an additional header
    s_string(b"\x00\x00\x00", name="Additional header", fuzzable=False)


def s_variant_bool(name: str = None, value: int = 0, fuzzable=True) -> None:
    """Add a variant declaration of a bool value."""
    s_byte(b"\x01", name=f"variant-header-{name}", fuzzable=False)
    s_byte(value, name=name, mutations=BOOLEAN, fuzzable=fuzzable)


def s_variant_nodeid(name: str = None, node_id=None, fuzzable=True) -> None:
    """Add a variant NodeId."""
    # Add a marker (17) to indicate a variant containing a NodeId
    s_byte(b"\x11", name=f"variant-header-{name}", fuzzable=False)
    # Placeholder for our generated NodeId
    s_group(value=node_id, values=NODE_IDS, name=name)


def s_variant_bytestring(
    name: str = None, byte_string: bytes = None, fuzzable=False
) -> None:
    """Add a variant ByteString."""
    # Add a marker (15) to indicate a variant containing a ByteString
    s_byte(b"\x0F", name=f"variant-header-{name}", fuzzable=False)
    if fuzzable:
        opcua_bytes(name, byte_string, to_fuzz=True)
    else:
        s_dword(len(byte_string), name=f"size-bytestring-{name}", fuzzable=False)
        s_string(byte_string, name=name, fuzzable=False)


def s_variant_string(
    name: str = None, string_: Union[str, bytes] = None, fuzzable=False
) -> None:
    """Add a variant String."""

    # Add a marker (12) to indicate a variant containing a String
    s_byte(b"\x0C", name=f"variant-header-{name}", fuzzable=False)

    if fuzzable:
        # PrivateKeyFormat takes ony specific values
        if name == "private_key_format":
            private_key_format = random.choice(PRIVATE_KEY_FORMAT)
            s_dword(len(private_key_format), name=f"size-string-{name}", fuzzable=False)
            s_string(private_key_format, name=name, fuzzable=False)
        else:
            opcua_bytes(name, string_, to_fuzz=True)
    else:
        s_dword(len(string_), name=f"size-string-{name}", fuzzable=False)
        s_string(string_, name=name, fuzzable=False)


def s_variant_array_string(
    name: str = None, strings: list[bytes] = None, fuzzable=False
) -> None:
    """Add a variant array String."""
    # Add a marker 0b10000000" + (12) to indicate a variant containing an array of String
    s_byte(b"\x8C", name=f"variant-header-{name}", fuzzable=False)
    s_dword(
        len(strings) if strings is not None else 0,
        name=f"size-array-string-{name}",
        fuzzable=False,
    )
    for str_ in strings:
        opcua_bytes(name + str_.decode().replace(".", "_"), str_, to_fuzz=True)


def extension_object_common_block(name: str):
    """
    Generates an Extensible parameter block.

    OPC 1000-4 - 7.17
    """
    elem_id = uuid4()

    s_string(
        b"\xFF\xFF\xFF\xFF", name="extension_id", fuzzable=True
    )  # overwritten by callback
    s_group(
        value=b"\x01",
        values=ENCODING_MASK,
        name=f"encoding_mask_{elem_id}".replace("-", "_"),
    )
    with s_block(
        "body",
        dep=f"encoding_mask_{elem_id}".replace("-", "_"),
        dep_value=b"\x00",
        dep_compare="!=",
    ):
        opcua_bytes(name, b"body_item")


def localized_text(name: str):
    """
    Generates a LocalizedText block.

    OPC 1000-6 - 5.2.2.14
    """
    elem_id = uuid4()
    encoding_mask = random.choice(ENCODING_MASK)
    s_byte(
        value=encoding_mask,
        name=f"encoding_mask_{name}_{elem_id}".replace("-", "_"),
        fuzzable=False,
    )
    if encoding_mask != b"\x00":
        opcua_bytes(f"{name}_{elem_id}".replace("-", "_"), None, True)


def opcua_bytes(name: str, value: bytes | None, to_fuzz=True):
    """Generates random bytes."""
    elem_id = uuid4()
    if to_fuzz:
        s_size(
            block_name=f"{name}_{elem_id}",
            fuzzable=False,
            length=4,
            math=lambda x: -1 if x == 0 else x,
            name=f"size_of_bytes_{name}",
        )
        with s_block(f"{name}_{elem_id}"):
            s_random(
                value if value is not None else b"\xDE\xAD\xBE\xEF",
                min_length=0,
                max_length=300,
                max_mutations=500,
                name=f"randomized_bytes_{name}",
            )
    else:
        s_static(b"\xff\xff\xff\xff", name=name)


def uuid_to_opcua_guid(uuid: Union[str, UUID]) -> bytes:
    """Convert Python UUID to OPCUA GUID as defined in OPC 10000-6 5.2.2.7"""
    # Convert UUID to UUID if given as a string
    if isinstance(uuid, str):
        uuid = UUID(uuid)

    # Serialize UUID as OPCUA GUID
    uuid_ = uuid.bytes
    return uuid_[0:4][::-1] + uuid_[4:6][::-1] + uuid_[6:8][::-1] + uuid_[8:16]


def generate_csr():
    """Generate a CSR for the StartSigningRequest method."""
    # Generate a private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Generate a CSR
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    # Provide certificate details
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "IDF"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Random"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "Random.org"),
                ]
            )
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    # Give the application URI
                    x509.UniformResourceIdentifier(
                        OpcuaGlobalParams.get_app_uri().decode()
                    ),
                ]
            ),
            critical=False,
            # Sign the CSR with our private key.
        )
        .sign(key, hashes.SHA256())
    )

    return csr.public_bytes(serialization.Encoding.DER)
