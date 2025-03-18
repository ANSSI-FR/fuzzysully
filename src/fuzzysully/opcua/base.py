"""This module defines the following OPCUA base messages:
- Hello
- Reverse Hello (including the associated error one)
"""

from struct import pack

from fuzzowski import (
    s_initialize,
    s_string,
    s_size,
    s_dword,
    s_group,
    s_block,
    s_response,
)
from fuzzysully.opcua import OpcuaGlobalParams
from fuzzysully.opcua.responses import ConnProtocolMsgResponse
from .helpers import (
    DWORD_RANGE,
    opcua_bytes,
)


def hello_definition():
    """Defines an OPCUA Hello message structure."""
    s_initialize("hello")

    # We start with the Message Header (OPC 1000-6 section 6.7.2.3)
    with s_block("h-header"):
        s_string(b"HEL", name="Hello magic", fuzzable=False)
        s_string(b"F", name="Chunk type", fuzzable=False)
        s_size("h-body", offset=8, name="body size", fuzzable=False)

    # Fill Hello request body
    with s_block("h-body"):
        s_group(value=pack("<I", 0), values=DWORD_RANGE, name="Protocol_version")
        s_group(value=pack("<I", 65536), values=DWORD_RANGE, name="Receive_buffer_size")
        s_group(value=pack("<I", 65536), values=DWORD_RANGE, name="Send_buffer_size")
        s_group(value=pack("<I", 0), values=DWORD_RANGE, name="Max_message_size")
        s_group(value=pack("<I", 0), values=DWORD_RANGE, name="Max_chunk_count")
        endpoint = OpcuaGlobalParams.get_endpoint()
        opcua_bytes(value=endpoint, name="Endpoint_url")

    s_response(
        ConnProtocolMsgResponse,
        name="hello_response",
        required_vars=[],
        optional_vars=[],
    )


def reverse_hello_definition():
    """Defines an OPCUA ReverseHello message structure as defined
    in OPC 10000-6 Section 7.1.2.6.
    """
    s_initialize("ReverseHello")

    # We start with the Message Header (OPC 1000-6 section 6.7.2.3)
    with s_block("h-header"):
        s_string(b"RHE", name="Reverse hello magic", fuzzable=False)
        s_string(b"F", name="Chunk type", fuzzable=False)
        s_size("h-body", offset=8, name="body size", fuzzable=False)

    # Fill ReverseHello request body
    with s_block("h-body"):
        app_uri = OpcuaGlobalParams.get_app_uri()
        opcua_bytes(value=app_uri, name="server_uri")
        endpoint = OpcuaGlobalParams.get_endpoint()
        opcua_bytes(value=endpoint, name="endpoint_uri")


def reverse_hello_error_definition():
    """Defines an OPCUA Error message as defined in OPC 10000-6
    Section 7.1.2.5.
    """
    s_initialize("ReverseHelloError")

    # We start with the Message Header (OPC 1000-6 section 6.7.2.3)
    with s_block("h-header"):
        s_string(b"ERR", name="Error magic", fuzzable=False)
        s_string(b"F", name="Chunk type", fuzzable=False)
        s_size("h-body", offset=8, name="body size", fuzzable=False)

    # Fill Error message body
    with s_block("h-body"):
        s_group(value=pack("<I", 0), values=DWORD_RANGE, name="err_code")
        s_dword(b"\xFF\xFF\xFF\xFF", name="reason", fuzzable=False)
