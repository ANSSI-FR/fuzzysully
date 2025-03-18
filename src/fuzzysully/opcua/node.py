"""Definition of AddNodes
"""

from fuzzowski import s_initialize, s_string, s_block

from .helpers import (
    get_weird_opc_timestamp,
    qualified_name_common_block,
    extension_object_common_block,
    s_common_msg_header_block,
    s_request_header,
    s_type_id,
    s_symmetric_chan_security_header,
)
from ..helpers import s_opcua_array


def add_nodes_definition(is_signed: bool):
    """
    Defines the structure of a AddNodes message.

    OPC 10000-4 - 5.7.2
    """
    s_initialize("AddNodes")

    if not is_signed:
        # Message header (OPC 1000-6 section 6.7.2.3)
        s_common_msg_header_block()
    with s_block("c-body"):
        if not is_signed:
            s_symmetric_chan_security_header()

        # And now we add the AddNodes binary parameters node
        s_type_id(488)
        if not is_signed:
            s_request_header(token_is_null=False, timestamp=get_weird_opc_timestamp())

        # Add Nodes parameters as defined in OPC 10000-4 5.7.2.2.
        # AddNodesItem
        with s_block("nodes_to_add"):
            with s_opcua_array(name="add_nodes_item", min_size=2, max_size=5):             # overwritten by callback
                s_string(b"\xFF\xFF\xFF\xFF", name="parent_node_id", fuzzable=True)        # overwritten by callback
                s_string(b"\xFF\xFF\xFF\xFF", name="ref_type_id", fuzzable=True)           # overwritten by callback
                s_string(b"\xFF\xFF\xFF\xFF", name="request_new_node_id", fuzzable=True)   # overwritten by callback
                qualified_name_common_block("BrowseName")
                s_string(value=b"\x01\x00\x00\x00", name="node_class", fuzzable=True)      # overwritten by callback
                extension_object_common_block("NodeAttributes")
                s_string(b"\xFF\xFF\xFF\xFF", name="type_definition", fuzzable=True)       # overwritten by callback
