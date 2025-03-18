"""Definitions of CreateSubscription and Publish messages
"""

from struct import pack

from fuzzowski import (
    s_initialize,
    s_dword,
    s_block,
    s_byte,
    s_group,
)
from .helpers import (
    get_weird_opc_timestamp,
    BOOLEAN,
    DWORD_RANGE,
    QWORD_RANGE,
    s_common_msg_header_block,
    s_request_header,
    s_type_id,
    s_symmetric_chan_security_header,
)
from ..helpers import s_opcua_array


def create_subscription_definition(is_signed: bool):
    """
    Defines the structure of a CreateSubscription message.

    OPC 10000-4 - 5.13.2
    """
    s_initialize("CreateSubscription")

    if not is_signed:
        # Message header (OPC 1000-6 section 6.7.2.3)
        s_common_msg_header_block()
    with s_block("c-body"):
        if not is_signed:
            s_symmetric_chan_security_header()

        # And now we add the CreateSubscription binary parameters node
        s_type_id(787)
        if not is_signed:
            s_request_header(token_is_null=False, timestamp=get_weird_opc_timestamp())

        # CreateSubscription parameters as defined in OPC 10000-4 5.13.2.2.
        # Example value = 500 milliseconds
        s_group(
            value=pack("<Q", 4647503709213818880),
            values=QWORD_RANGE,
            name="Requested_publishing_interval",
        )
        s_group(
            value=pack("<I", 10), values=DWORD_RANGE, name="Requested_lifetime_count"
        )
        s_group(
            value=pack("<I", 3),
            values=DWORD_RANGE,
            name="Requested_max_keep_alive_count",
        )
        s_group(
            value=pack("<I", 1000),
            values=DWORD_RANGE,
            name="Max_notifications_per_publish",
        )
        s_group(value=b"\x01", values=BOOLEAN, name="publish_enabled")
        s_byte(0, name="Priority")


def publish_definition(is_signed: bool):
    """
    Defines the structure of a 'Publish' message.

    OPC 10000-4 - 5.13.5
    """
    s_initialize("Publish")

    if not is_signed:
        # Message header (OPC 1000-6 section 6.7.2.3)
        s_common_msg_header_block()
    with s_block("c-body"):
        if not is_signed:
            s_symmetric_chan_security_header()

        # And now we add the Publish binary parameters node
        s_type_id(826)
        if not is_signed:
            s_request_header(token_is_null=False, timestamp=get_weird_opc_timestamp())

        # Publish parameters as defined in OPC 10000-4 5.13.5.2.
        # Subscription Acknowledgement
        with s_block("subs_acknowledgement"):
            # Array content will be overwritten by our callback
            with s_opcua_array(name="subs_acknowledgements", min_size=2, max_size=5):
                s_dword(0, name="subs_id", fuzzable=False)  # overwritten by callback
                s_group(
                    value=b"\x01\x00\x00\x00",
                    values=DWORD_RANGE,
                    name="sequence_number",
                )
