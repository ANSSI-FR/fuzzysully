"""Definitions of CreateSession, ActivateSession and CloseSession messages
"""

import struct
from struct import pack

from fuzzowski import (
    s_initialize,
    s_string,
    s_dword,
    s_block,
    s_byte,
    s_group,
)
from fuzzysully.opcua import OpcuaGlobalParams
from .helpers import (
    get_weird_opc_timestamp,
    DWORD_RANGE,
    QWORD_RANGE,
    BOOLEAN,
    APPLICATION_TYPE,
    s_common_msg_header_block,
    s_request_header,
    s_type_id,
    s_symmetric_chan_security_header,
    opcua_bytes,
)
from ..helpers import s_opcua_array


def create_session_definition():
    """
    Defines the structure of a CreateSession message.

    OPC 10000-4 - 5.6.2
    """
    s_initialize("CreateSession")

    # Message header (OPC 1000-6 section 6.7.2.3)
    s_common_msg_header_block()
    with s_block("c-body"):
        s_symmetric_chan_security_header()

        # And now we add the CreateSession binary parameters node
        s_type_id(461)
        s_request_header(token_is_null=False, timestamp=get_weird_opc_timestamp())

        # Create session parameters as defined in OPC 10000-4 5.6.2.2

        # Application description as defined in OPC 10000-4 7.2
        application = "urn:unconfigured:application".encode("utf-8")
        opcua_bytes(value=application, name="application")
        opcua_bytes(value=b"\xFF\xFF\xFF\xFF", name="ProductUri")
        s_byte(0, name="ApplicationName")
        s_group(value=struct.pack("<I", 1), values=APPLICATION_TYPE, name="ApplicationType")
        opcua_bytes(value=b"\xFF\xFF\xFF\xFF", name="GatewayServerUri")
        opcua_bytes(value=b"\xFF\xFF\xFF\xFF", name="DiscoveryProfileUri")
        with s_opcua_array(name="DiscoveryUrls", min_size=1, max_size=5):
            opcua_bytes("discovery_urls", None, True)

        # Other parameters
        opcua_bytes(value=b"\xFF\xFF\xFF\xFF", name="ServerUri")
        endpoint = OpcuaGlobalParams.get_endpoint()
        opcua_bytes(value=endpoint, name="endpoint")
        opcua_bytes(value=b"\xFF\xFF\xFF\xFF", name="SessionName")
        s_string(b"\xFF\xFF\xFF\xFF", name="ClientNonce", fuzzable=False)
        s_string(b"\xFF\xFF\xFF\xFF", name="ClientCertificate", fuzzable=False)
        s_group(
            value=pack("d", 1200000.0),
            values=QWORD_RANGE,
            name="RequestedSessionTimeout",
        )
        s_group(
            value=pack("<I", 2147483647),
            values=DWORD_RANGE,
            name="MaxResponseMessageSize",
        )


def activate_session_definition():
    """
    Defines the structure of an Activate Session message.

    OPC 10000-4 - 5.6.3
    """
    s_initialize("ActivateSession")

    # Message header (OPC 1000-6 section 6.7.2.3)
    s_common_msg_header_block()
    with s_block("c-body"):
        s_symmetric_chan_security_header()

        # And now we add the ActivateSession binary parameters node
        s_type_id(467)
        s_request_header(token_is_null=False, timestamp=get_weird_opc_timestamp())

        # Activate session parameters as defined in OPC 10000-4 5.6.3.2

        # SignatureData
        opcua_bytes(value=b"\xFF\xFF\xFF\xFF", name="ClientAlgorithm")
        opcua_bytes(value=b"\xFF\xFF\xFF\xFF", name="ClientSignature")

        # Other parameters
        s_string(b"\xFF\xFF\xFF\xFF", name="Client software certificates", fuzzable=False) # Reserved for future use
        with s_opcua_array(name="LocaleId", min_size=1, max_size=5):
            opcua_bytes("localeid", None, True)

        # UserIdentityToken
        s_string(
            b"\x01\x00" + struct.pack("<H", 321), name="User type id", fuzzable=False
        )
        s_string(b"\x01", name="binary body")
        policy_id = "anonymous".encode("utf-8")
        # 1 length fields + algorithm
        s_dword(len(policy_id) + 4, name="Length user id token", fuzzable=False)
        s_dword(len(policy_id), name="Id length", fuzzable=False)
        s_string(policy_id, name="Policy id", fuzzable=False)

        # UserTokenSignature
        opcua_bytes(value=b"\xFF\xFF\xFF\xFF", name="UserSignAlgorithm")
        opcua_bytes(value=b"\xFF\xFF\xFF\xFF", name="UserSignature")


def close_session_definition():
    """
    Defines the structure of a Close Session message.

    OPC 10000-4 - 5.6.4
    """
    s_initialize("CloseSession")

    # Message header (OPC 1000-6 section 6.7.2.3)
    s_common_msg_header_block()
    with s_block("c-body"):
        s_symmetric_chan_security_header()

        # And now we add the CloseSession binary parameters node
        s_type_id(473)
        s_request_header(token_is_null=False, timestamp=get_weird_opc_timestamp())

        # Close session parameters as defined in OPC 10000-4 5.6.4.2

        # DeleteSubscriptions
        s_group(value=b"\x00", values=BOOLEAN, name="DeleteSubscriptions")
