"""Definitions of Read and HistoryRead messages
"""

from fuzzowski import s_initialize, s_string, s_block, s_group
from .helpers import (
    get_weird_opc_timestamp,
    attribute_id,
    qualified_name_common_block,
    extension_object_common_block,
    TIMESTAMP_TO_RETURN,
    BOOLEAN,
    QWORD_RANGE,
    s_common_msg_header_block,
    s_request_header,
    s_type_id,
    s_symmetric_chan_security_header,
    opcua_bytes,
)
from ..helpers import s_opcua_array


def read_definition(is_signed: bool):
    """
    Defines the structure of a Read message.

    OPC 10000-4 - 5.10.2
    """
    s_initialize("Read")

    if not is_signed:
        # Message header (OPC 1000-6 section 6.7.2.3)
        s_common_msg_header_block()
    with s_block("c-body"):
        if not is_signed:
            s_symmetric_chan_security_header()

        # And now we add the Read binary parameters node
        s_type_id(631)
        if not is_signed:
            s_request_header(token_is_null=False, timestamp=get_weird_opc_timestamp())

        # Read parameters as defined in OPC 10000-4 5.10.2.2.
        s_group(
            value=b"\x00\x00\x00\x00\x00\x00\x00\x00", values=QWORD_RANGE, name="MaxAge"
        )
        s_group(
            value=b"\x03\x00\x00\x00",
            values=TIMESTAMP_TO_RETURN,
            name="TimestampsToReturn",
        )

        # ReadValueId as defined in OPC 1000-4 7.29
        with s_block("nodes_to_read"):
            with s_opcua_array(name="read_value_ids", min_size=2, max_size=5):
                # will be overwritten by our callback
                s_string(b"\xFF\xFF\xFF\xFF", name="node_id", fuzzable=True)
                attribute_id()
                opcua_bytes(
                    value=b"\xFF\xFF\xFF\xFF", name="Index_range", to_fuzz=False
                )
                qualified_name_common_block("data_encoding", fuzzable=False)


def history_read_definition(is_signed: bool):
    """
    Defines the structure of a HistoryRead message.

    OPC 10000-4 - 5.10.3
    """
    s_initialize("HistoryRead")

    if not is_signed:
        # Message header (OPC 1000-6 section 6.7.2.3)
        s_common_msg_header_block()
    with s_block("c-body"):
        if not is_signed:
            s_symmetric_chan_security_header()
        s_type_id(664)  # Type id: HistoryRead (encoded node ID)
        if not is_signed:
            s_request_header(token_is_null=False, timestamp=get_weird_opc_timestamp())

        # History Read parameters as defined in OPC 10000-4 5.10.3.2.

        # HistoryReadDetails as defined in OPC 1000-11 6.5
        extension_object_common_block("HistoryReadDetails")

        # Other parameters
        s_group(
            value=b"\x03\x00\x00\x00",
            values=TIMESTAMP_TO_RETURN,
            name="TimestampsToReturn",
        )
        s_group(value=b"\x00", values=BOOLEAN, name="releaseContinuationPoints")

        with s_block("nodes_to_read"):
            # HistoryReadValueId
            with s_opcua_array(name="read_value_ids", min_size=2, max_size=5):
                # NodeId will be overwritten by our callback
                s_string(b"\xFF\xFF\xFF\xFF", name="node_id", fuzzable=True)
                opcua_bytes(
                    value=b"\xFF\xFF\xFF\xFF", name="Index_range", to_fuzz=False
                )
                qualified_name_common_block("data_encoding", fuzzable=False)
                opcua_bytes(name="ContinuationPoint", value=b"\xff\xff\xff\xff")
