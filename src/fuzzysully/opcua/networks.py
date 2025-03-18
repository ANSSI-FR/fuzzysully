"""Definitions of FindServers, FindServersOnNetwork, GetEndpoints
and RegisterServer2 messages
"""

import struct

from fuzzowski import s_initialize, s_string, s_block, s_group
from fuzzysully.opcua import OpcuaGlobalParams
from .helpers import (
    get_weird_opc_timestamp,
    APPLICATION_TYPE,
    BOOLEAN,
    DWORD_RANGE,
    s_common_msg_header_block,
    s_request_header,
    s_type_id,
    s_symmetric_chan_security_header,
    opcua_bytes,
    extension_object_common_block,
    localized_text,
)
from ..helpers import s_opcua_array


def find_servers_definition(is_signed: bool):
    """
    Defines the structure of a FindServers message.

    OPC 10000-4 - 5.4.2
    """
    s_initialize("FindServers")

    if not is_signed:
        # Message header (OPC 1000-6 section 6.7.2.3)
        s_common_msg_header_block()
    with s_block("c-body"):
        if not is_signed:
            s_symmetric_chan_security_header()

        # And now we add the FindServers binary parameters node

        # Type id: FindServers (encoded node ID)
        s_type_id(422)
        if not is_signed:
            s_request_header(token_is_null=True, timestamp=get_weird_opc_timestamp())

        # Find Server parameters as defined in OPC 10000-4 5.4.2.2.
        endpoint = OpcuaGlobalParams.get_endpoint()
        opcua_bytes(value=endpoint, name="endpoint_url")
        with s_opcua_array(name="local_ids", min_size=1, max_size=5):
            opcua_bytes("local_id", None, True)
        with s_opcua_array(name="server_uris", min_size=1, max_size=5):
            opcua_bytes("uri", None, True)


def find_servers_on_network_definition(is_signed: bool):
    """
    Defines the structure of a FindServersOnNetwork message.

    OPC 10000-4 - 5.4.3
    """
    s_initialize("FindServersOnNetwork")

    if not is_signed:
        # Message header (OPC 1000-6 section 6.7.2.3)
        s_common_msg_header_block()
    with s_block("c-body"):
        if not is_signed:
            s_symmetric_chan_security_header()

        # And now we add the FindServersOnNetwork binary parameters node
        s_type_id(12208)
        if not is_signed:
            s_request_header(token_is_null=True, timestamp=get_weird_opc_timestamp())

        # Find Server On Network parameters as defined in OPC 10000-4 5.4.3.2.
        s_group(
            value=struct.pack("<I", 0), values=DWORD_RANGE, name="Starting_record_id"
        )
        s_group(
            value=struct.pack("<I", 0), values=DWORD_RANGE, name="Max_records_to_return"
        )
        with s_opcua_array(name="Server_capability_filter", min_size=1, max_size=5):
            opcua_bytes("item", None, True)


def get_endpoints_definition(is_signed: bool):
    """
    Defines the structure of a GetEndpoints message.

    OPC 10000-4 - 5.4.4
    """
    s_initialize("GetEndpoints")

    if not is_signed:
        # Message header (OPC 1000-6 section 6.7.2.3)
        s_common_msg_header_block()
    with s_block("c-body"):
        if not is_signed:
            s_symmetric_chan_security_header()

        # And now we add the GetEndpoints binary parameters node

        # Type id: GetEndpoints (encoded node ID)
        s_type_id(428)
        if not is_signed:
            s_request_header(token_is_null=True, timestamp=get_weird_opc_timestamp())

        # GetEndpoints parameters as defined in OPC 10000-4 5.4.4.2.
        endpoint = OpcuaGlobalParams.get_endpoint()
        opcua_bytes(value=endpoint, name="endpoint_url")

        with s_opcua_array(name="local_ids", min_size=1, max_size=5):
            opcua_bytes("local_id", None, True)
        with s_opcua_array(name="profile_ids", min_size=1, max_size=5):
            opcua_bytes("profile_id", None, True)


def register_server_2_definition(is_signed: bool):
    """
    Defines the structure of a RegisterServer2 message.

    OPC 10000-4 - 5.4.6
    """
    s_initialize("RegisterServer2")

    if not is_signed:
        # Message header (OPC 1000-6 section 6.7.2.3)
        s_common_msg_header_block()
    with s_block("c-body"):
        if not is_signed:
            s_symmetric_chan_security_header()

        # And now we add the RegisterServer2 binary parameters node
        s_type_id(12211)
        if not is_signed:
            s_request_header(token_is_null=True, timestamp=get_weird_opc_timestamp())

        # RegisterServer2 parameters as defined in OPC 10000-4 5.4.6.2

        # RegisteredServer as defined in OPC 1000-4 7.32
        server_uri = "urn:opcua.server".encode("utf-8")
        opcua_bytes(value=server_uri, name="server_uri")
        product_uri = "http://my.opcua-implementation.code".encode("utf-8")
        opcua_bytes(value=product_uri, name="product_uri")
        with s_opcua_array(name="Servernames", min_size=1, max_size=5):
            localized_text("server_names")
        s_group(value=b"\x00\x00\x00\x00", values=APPLICATION_TYPE, name="Server_type")
        opcua_bytes(value=b"\xFF\xFF\xFF\xFF", name="GatewayServerUri")
        discovery_uri = OpcuaGlobalParams.get_endpoint()
        with s_opcua_array(name="DiscoveryUrls", min_size=1, max_size=5):
            opcua_bytes("discovery_url", discovery_uri, True)
        opcua_bytes(value=b"\xFF\xFF\xFF\xFF", name="SemaphoreFilePath")
        s_group(value=b"\x00", values=BOOLEAN, name="IsOnline")

        # Other parameters
        s_string(b"\x01\x00\x00\x00", "DiscoveryConfigurationArraySize", fuzzable=False)
        extension_object_common_block("DiscoveryConfiguration")
