"""Definitions of Browse, BrowseNext, RegisterNodes, UnregisterNodes
 and TranslateBrowsePathsToNodeIds messages
"""

from struct import pack

from fuzzowski import s_initialize, s_string, s_block, s_group
from .helpers import (
    get_weird_opc_timestamp,
    BROWSE_DIRECTION,
    BOOLEAN,
    DWORD_RANGE,
    QWORD_RANGE,
    NODE_IDS,
    s_common_msg_header_block,
    s_request_header,
    s_type_id,
    s_symmetric_chan_security_header,
    opcua_bytes,
)
from .helpers import qualified_name_common_block
from ..helpers import s_opcua_array


def browse_definition(is_signed: bool):
    """
    Defines the structure of a Browse message.

    OPC 10000-4 - 5.8.2
    """
    s_initialize("Browse")

    if not is_signed:
        s_common_msg_header_block()
    with s_block("c-body"):
        if not is_signed:
            s_symmetric_chan_security_header()

        # And now we add the Browse binary parameters node
        s_type_id(527)
        if not is_signed:
            s_request_header(token_is_null=False, timestamp=get_weird_opc_timestamp())

        # Browse parameters as defined in OPC 10000-4 5.8.2.2.

        # ViewDescription as defined in OPC 1000-4 7.45
        s_group(
            value=b"\x00\x00",
            values=NODE_IDS,
            name="view_id",
        )
        s_group(
            value=b"\x00\x00\x00\x00\x00\x00\x00\x00",
            values=QWORD_RANGE,
            name="timestamp",
        )
        s_group(value=b"\x00\x00\x00\x00", values=DWORD_RANGE, name="view_version")

        # Other parameters
        s_group(
            value=pack("<I", 100),
            values=DWORD_RANGE,
            name="RequestedMaxReferencesPerNodes",
        )

        with s_block("nodes_to_browse"):
            # BrowseDescription array
            with s_opcua_array(name="browse_description", min_size=2, max_size=5):
                # This NodeId will be overwritten by our callback
                s_string(b"\xFF\xFF\xFF\xFF", name="node_id", fuzzable=True)
                s_group(
                    value=b"\x02\x00\x00\x00",
                    values=BROWSE_DIRECTION,
                    name="browse_direction",
                )
                s_string(b"\xFF\xFF\xFF\xFF", name="ref_type_id", fuzzable=True)
                s_group(value=b"\x00", values=BOOLEAN, name="IncludeSubType")
                s_group(
                    value=pack("<I", 255), values=DWORD_RANGE, name="NodeClasseMask"
                )
                s_group(value=pack("<I", 63), values=DWORD_RANGE, name="ResultMask")


def browse_next_definition(is_signed: bool):
    """
    Defines the structure of a BrowseNext message.

    OPC 10000-4 - 5.8.3
    """
    s_initialize("BrowseNext")

    if not is_signed:
        # Message header (OPC 1000-6 section 6.7.2.3)
        s_common_msg_header_block()
    with s_block("c-body"):
        if not is_signed:
            s_symmetric_chan_security_header()

        # And now we add the BrowseNext binary parameters node
        s_type_id(533)
        if not is_signed:
            s_request_header(token_is_null=False, timestamp=get_weird_opc_timestamp())

        # BrowseNext parameters as defined in OPC 10000-4 5.8.3.2.
        s_group(value=b"\x00", values=BOOLEAN, name="releaseContinuationPoints")

        with s_block("continuation_points"):
            # ContinuationPoints as defined in OPC 1000-4 7.9
            with s_opcua_array(name="continuation_point", min_size=2, max_size=5):
                opcua_bytes(name="ContinuationPoint", value=b"\xff\xff\xff\xff")


def register_nodes_definition(is_signed: bool):
    """Defines the structure of a RegisterNodes message.

    OPC 10000-4 - 5.8.5
    """
    s_initialize("RegisterNodes")

    if not is_signed:
        # Message header (OPC 1000-6 section 6.7.2.3)
        s_common_msg_header_block()
    with s_block("c-body"):
        if not is_signed:
            s_symmetric_chan_security_header()

        # And now we add the RegisterNodes binary parameters node
        s_type_id(560)
        if not is_signed:
            s_request_header(token_is_null=False, timestamp=get_weird_opc_timestamp())

        # RegisterNodes parameters as defined in OPC 10000-4 5.8.5.2.
        with s_opcua_array(name="register_node_ids", min_size=2, max_size=25):
            # This NodeId will be overwritten by our callback
            s_string(b"\xFF\xFF\xFF\xFF", name="node_id", fuzzable=True)


def unregister_nodes_definition(is_signed: bool):
    """Defines the structure of a UnregisterNodes message.

    OPC 10000-4 - 5.8.6
    """
    s_initialize("UnregisterNodes")

    if not is_signed:
        # Message header (OPC 1000-6 section 6.7.2.3)
        s_common_msg_header_block()
    with s_block("c-body"):
        if not is_signed:
            s_symmetric_chan_security_header()

        # And now we add the UnregisterNodes binary parameters node
        s_type_id(566)
        if not is_signed:
            s_request_header(token_is_null=False, timestamp=get_weird_opc_timestamp())

        # UnregisterNodes parameters as defined in OPC 10000-4 5.8.6.2.
        # Items will be overridden with our session callback
        with s_opcua_array(name="unregister_node_ids", min_size=2, max_size=25):
            # This NodeId will be overwritten by our callback
            s_string(b"\xFF\xFF\xFF\xFF", name="node_id", fuzzable=True)


def translate_browse_path_to_node_ids_definition(is_signed: bool):
    """
    Defines the structure of a TranslateBrowsePathsToNodeIds message.

    OPC 10000-4 - 5.8.4
    """
    s_initialize("TranslateBrowsePathsToNodeIds")

    if not is_signed:
        # Message header (OPC 1000-6 section 6.7.2.3)
        s_common_msg_header_block()
    with s_block("c-body"):
        if not is_signed:
            s_symmetric_chan_security_header()

        # And now we add the TranslateBrowsePathsToNodeIds binary parameters node
        s_type_id(554)
        if not is_signed:
            s_request_header(token_is_null=False, timestamp=get_weird_opc_timestamp())

        # TranslateBrowsePathsToNodeIds parameters as defined in OPC 10000-4 5.8.4.2.
        # Items will be overridden with our session callback
        with s_block("browse_path"):
            with s_opcua_array(name="browse_paths", min_size=2, max_size=5):
                # This NodeId will be overwritten by our callback
                s_string(b"\x00\x00\x00\x00", name="starting_node", fuzzable=True)
                with s_opcua_array(name="elements", min_size=2, max_size=5):
                    # This NodeId will be overwritten by our callback
                    s_string(
                        b"\x00\x00\x00\x00", name="reference_type_id", fuzzable=True
                    )
                    s_group(value=b"\x00", values=BOOLEAN, name="isInverse")
                    s_group(value=b"\x00", values=BOOLEAN, name="includeSubtypes")
                    qualified_name_common_block("target_name", fuzzable=True)
