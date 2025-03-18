"""Defines OPCUA messages structure related to Secure Channels
"""

import struct

from fuzzowski import s_initialize, s_string, s_size, s_dword, s_block, s_group
from .helpers import (
    get_weird_opc_timestamp,
    s_request_header,
    s_type_id,
    DWORD_RANGE,
    SECURITY_MODE,
    REQUEST_TYPE,
    opcua_bytes,
)


def open_secure_channel_definition():
    """Defines the structure of an Open Secure Channel message.

    Message format for Secure Conversations is specified in
    OPC 10000-6 section 6.7.2.
    """
    s_initialize("OpenSecureChannel")

    # We start with the message header
    with s_block("o-header"):
        # We use a 'OPN' message type (used for secure channel opening)
        s_string(b"OPN", name="Open channel magic", fuzzable=False)

        # Message is not fragmented
        s_string(b"F", name="Chunk type", fuzzable=False)

        # Message size = size of message body + size of header (12)
        s_size("o-body", offset=12, name="Body size", fuzzable=False)

        # Add Secure Channel ID, 0 as we don't have one for now
        s_group(value=struct.pack("<I", 0), values=DWORD_RANGE, name="Channel_ID")

        # We then continue with the message body
    with s_block("o-body"):

        # Message body starts with an asymmetrical security header
        # This is defined in OPC 10000-6 section 6.7.2.3.

        # Chunking encryption (security policy 'None')
        policy_uri = "http://opcfoundation.org/UA/SecurityPolicy#None".encode("utf-8")
        opcua_bytes(value=policy_uri, name="policy_uri")

        # We don't provide any certificate, so we give a length of -1 for the
        # sender certificate and the receiver certificate thumbprint.
        s_string(b"\xff\xff\xff\xff", name="Sender certificate", fuzzable=False)
        s_string(b"\xff\xff\xff\xff", name="Receiver Certificate thumbprint", fuzzable=False)

        # Sequence header as defined in 6.7.2.4.
        s_group(value=struct.pack("<I", 1), values=DWORD_RANGE, name="Sequence_number")
        s_group(value=struct.pack("<I", 1), values=DWORD_RANGE, name="Request_ID")

        # And now we add the OpenSecureChannel binary parameters node
        s_type_id(446)
        s_request_header(token_is_null=True, timestamp=get_weird_opc_timestamp())

        # Open channel parameters as defined in 5.5.2.2.
        s_group(
            value=struct.pack("<I", 0),
            values=DWORD_RANGE,
            name="Client_protocol_version",
        )
        s_group(value=struct.pack("<I", 0), values=REQUEST_TYPE, name="Request_type")
        s_group(value=struct.pack("<I", 1), values=SECURITY_MODE, name="Security_mode")
        s_string(b"\x00\x00\x00\x00", name="Client nonce",fuzzable=False)
        s_group(
            value=struct.pack("<I", 3600000),
            values=DWORD_RANGE,
            name="Requested_lifetime",
        )


def close_secure_channel_definition():
    """Defines the structure of a Close Secure Channel OPC message."""
    s_initialize("CloseSecureChannel")

    with s_block("c-header"):
        # We use a 'CLO' message type (used for secure channel closing)
        s_string(b"CLO", name="Close channel magic", fuzzable=False)

        # Message is not fragmented
        s_string(b"F", name="Chunk type", fuzzable=False)

        # Message size = size of message body + size of header (12)
        s_size("c-body", offset=8, name="body size", fuzzable=False)

        # Add Secure Channel ID, stored in a variable after
        # OpenSecureChannelResponse processing (see fuzzysully.opcua.responses) #No more
        s_dword(0, name="sc_id", fuzzable=False)  # overwritten by callback

    # We then continue with the message body
    with s_block("c-body"):

        # Message body starts with a symmetrical security header
        # This is defined in OPC 10000-6 section 6.7.2.3.
        s_dword(0, name="sc_token", fuzzable=False)  # overwritten by callback

        # Followed by a sequence header defined in OPC 10000-6 section 6.7.2.4.
        s_dword(2, name="seq_num", fuzzable=False)  # overwritten by callback
        s_dword(2, name="req_id", fuzzable=False)  # overwritten by callback

        # The message chunk body starts here. As requested by OPC 10000-4
        # section 5.5.3.2, we start by defining a binary-encoded
        # CloseSecureChannel request.
        s_type_id(452)
        s_request_header(token_is_null=True, timestamp=get_weird_opc_timestamp())

        # And we continue with the last request parameter:
        # - the secure channel identifier
        s_dword(0, name="sc_id2", fuzzable=False)  # overwritten by callback


def close_secure_channel_sign_definition():
    """Close secure channel with sign"""

    s_initialize("CloseSecureChannelSign")

    # We then continue with the message body
    with s_block("c-body"):

        # The message chunk body starts here. As requested by OPC 10000-4
        # section 5.5.3.2, we start by defining a binary-encoded
        # CloseSecureChannel request.
        s_type_id(452)

        # RequestHeader will be automatically added by our fuzzer

        # And we continue with the last request parameter:
        # - the secure channel identifier
        s_dword(1, name="sc_id")  # overwritten by callback
