"""Definitions of CreateMonitoredItems, ModifyMonitoredItems
and DeleteMonitoredItems messages
"""

import struct

from fuzzowski import s_initialize, s_string, s_dword, s_block, s_group
from .helpers import (
    get_weird_opc_timestamp,
    attribute_id,
    qualified_name_common_block,
    extension_object_common_block,
    TIMESTAMP_TO_RETURN,
    MONITORING_MODE,
    BOOLEAN,
    QWORD_RANGE,
    DWORD_RANGE,
    opcua_bytes,
    s_common_msg_header_block,
    s_request_header,
    s_type_id,
    s_symmetric_chan_security_header,
)
from ..helpers import s_opcua_array


def create_monitored_items_definition(is_signed: bool):
    """
    Defines the structure of a CreateMonitoredItems message.

    OPC 10000-4 - 5.12.2
    """
    s_initialize("CreateMonitoredItems")

    if not is_signed:
        # Message header (OPC 1000-6 section 6.7.2.3)
        s_common_msg_header_block()
    with s_block("c-body"):
        if not is_signed:
            s_symmetric_chan_security_header()

        # And now we add the CreateMonitoredItems binary parameters node

        # Type id: CreateMonitoredItems (encoded node ID)
        s_type_id(751)
        if not is_signed:
            s_request_header(token_is_null=False, timestamp=get_weird_opc_timestamp())

        # CreateMonitoredItems parameters as defined in OPC 10000-4 5.12.2.2.
        s_dword(0, name="subs_id", fuzzable=False)  # overwritten by callback
        s_group(
            value=b"\x03\x00\x00\x00",
            values=TIMESTAMP_TO_RETURN,
            name="TimestampsToReturn",
        )

        # MonitoredItemCreateRequest
        with s_block("item_to_create"):
            with s_opcua_array(name="monitor_item_create", min_size=2, max_size=5):
                # ReadValueId parameters as defined in OPC 1000-4 7.29
                # will be overwritten by a callback with a valid random NodeId
                s_string(b"\xFF\xFF\xFF\xFF", name="node_id", fuzzable=True)

                # Add an attribute ID
                attribute_id()
                opcua_bytes(value=b"\xFF\xFF\xFF\xFF", name="Index_range", to_fuzz=False)
                qualified_name_common_block("data_encoding", fuzzable=False)

                # Other parameters
                s_group(
                    value=b"\x02\x00\x00\x00",
                    values=MONITORING_MODE,
                    name="MonitoringMode",
                )

                # Monitoring parameters as defined in OPC 1000-4 7.21
                s_group(
                    value=struct.pack("<I", 1), values=DWORD_RANGE, name="Client_handle"
                )
                s_group(
                    value=struct.pack("<Q", 0),
                    values=QWORD_RANGE,
                    name="Sampling_interval",
                )

                # MonitoringFilter parameters as defined in OPC 1000-4 7.22
                extension_object_common_block("MonitoringFilter")

                s_group(
                    value=struct.pack("<I", 100), values=DWORD_RANGE, name="Queue_size"
                )
                s_group(value=b"\x01", values=BOOLEAN, name="discard_oldest")


def delete_monitored_items_definition(is_signed: bool):
    """
    Defines the structure of a DeleteMonitoredItems message.

    OPC 10000-4 - 5.12.6
    """

    s_initialize("DeleteMonitoredItems")

    if not is_signed:
        # Message header (OPC 1000-6 section 6.7.2.3)
        s_common_msg_header_block()
    with s_block("c-body"):
        if not is_signed:
            s_symmetric_chan_security_header()

        # And now we add the DeleteMonitoredItems binary parameters node

        # Type id: DeleteMonitoredItems (encoded node ID)
        s_type_id(781)
        if not is_signed:
            s_request_header(token_is_null=False, timestamp=get_weird_opc_timestamp())

        # DeleteMonitoredItems parameters as defined in OPC 10000-4 5.12.6.2.
        s_dword(0, name="subs_id", fuzzable=False)  # overwritten by callback

        # MonitoredItemIds
        with s_block("item_to_delete"):
            # Array content will be overwritten by our callback
            with s_opcua_array(name="monitor_item_delete", min_size=2, max_size=5):
                s_dword(0, name="monitored_item_id", fuzzable=False)


def modify_monitored_items_definition(is_signed: bool):
    """
    Defines the structure of a ModifyMonitoredItems message.

    OPC 10000-4 - 5.12.3
    """
    s_initialize("ModifyMonitoredItems")

    if not is_signed:
        # Message header (OPC 1000-6 section 6.7.2.3)
        s_common_msg_header_block()
    with s_block("c-body"):
        if not is_signed:
            s_symmetric_chan_security_header()

        # And now we add the ModifyMonitoredItems binary parameters node
        s_type_id(763)
        if not is_signed:
            s_request_header(token_is_null=False, timestamp=get_weird_opc_timestamp())

        # ModifyMonitoredItems parameters as defined in OPC 10000-4 5.12.3.2.
        s_dword(0, name="subs_id", fuzzable=False)  # overwritten by callback
        s_group(
            value=b"\x03\x00\x00\x00",
            values=TIMESTAMP_TO_RETURN,
            name="TimestampsToReturn",
        )

        # MonitoredItemModifyRequest
        with s_block("item_to_modify"):
            with s_opcua_array(name="monitor_item_modify", min_size=2, max_size=5):
                s_dword(
                    0, name="monitored_item_id", fuzzable=False
                )  # overwritten by callback

                # Monitoring parameters as defined in OPC 1000-4 7.21
                s_group(
                    value=struct.pack("<I", 1), values=DWORD_RANGE, name="Client_handle"
                )
                s_group(
                    value=struct.pack("<Q", 0),
                    values=QWORD_RANGE,
                    name="Sampling_interval",
                )

                # MonitoringFilter parameters as defined in OPC 1000-4 7.22
                extension_object_common_block("MonitoringFilter")

                s_group(
                    value=struct.pack("<I", 100), values=DWORD_RANGE, name="Queue_size"
                )
                s_group(value=b"\x01", values=BOOLEAN, name="discard_oldest")
