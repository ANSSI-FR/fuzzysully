"""Callbacks for Monitored Items related requests
"""

# Imports from asyncua
from asyncua import ua
from asyncua.common.connection import MessageChunk
from asyncua.ua.ua_binary import struct_from_binary
from asyncua.ua.uaprotocol_hand import SecurityPolicy

# Imports from fuzzowski
from fuzzowski import ITargetConnection, IFuzzLogger, Request
from fuzzowski.exception import FuzzowskiTestCaseAborted

# Imports some of our helpers
from ...helpers import BlockHelper, OPCUASession


def create_monitor_to_publish_signed(
    target: ITargetConnection,
    logger: IFuzzLogger,
    session: OPCUASession,
    node: Request,
    request: BlockHelper = None,
    *_,
    **__,
):
    """Callback function called to update the Publish request fields
    following an CreateSubscriptionResponse response (signed mode)

    :param target: Fuzzing target
    :param logger: Fuzzer logger
    :param session: Current fuzzing session
    :param node: Next request to send as defined in Fuzzowski
    :param request: the current block helper object if already created
    """
    # Create our request helper
    request = BlockHelper(node)

    # Fetch response
    recv = session.last_recv

    # List of monitored item ids
    monitored_item_id = []

    # Parse the message header
    if len(recv) >= 8:
        try:
            # Convert bytes to buffer
            message = ua.utils.Buffer(recv)

            # Use python-opcua to parse the CreateMonitoredItems response :)
            resp = struct_from_binary(ua.CreateMonitoredItemsResponse, message)
            # Get the first Result

            # Save and get MonitoredItemId
            size = len(resp.Results)
            for i in range(size):
                monitored_item_id.append(resp.Results[i].MonitoredItemId)

            # Save monitored item ID in our session.
            session.monitored_item_id = monitored_item_id

            # ActivateSessionResponse response successfully parsed
            logger.log_info(f"CreateMonitoredItems response found.")
            logger.log_info("Updating Publish Request parameters accordingly.")

            try:  # Publish
                repeat_block = request.get("c-body").get("subs_acknowledgement").get("subs_acknowledgements")
                size = repeat_block.size()
                for i in range(size):
                    repeat_block.set_array_item(i, "subs_id", session.subs_id)
            except Exception as error:
                pass

        except ValueError as valerr:
            logger.log_error("Call response not found")
            raise FuzzowskiTestCaseAborted(
                "An error occurred while unpacking OPCUA message."
            ) from valerr
        except Exception as error:
            raise FuzzowskiTestCaseAborted() from error
    else:
        raise FuzzowskiTestCaseAborted()


def create_monitor_to_publish(
    target: ITargetConnection,
    logger: IFuzzLogger,
    session: OPCUASession,
    node: Request,
    *_,
    **__,
):
    """Callback function called to update the Publish request fields
    following an CreateSubscriptionResponse response.

    :param target: Fuzzing target
    :param logger: Fuzzer logger
    :param session: Current fuzzing session
    :param node: Next request to send as defined in Fuzzowski
    """

    # Fetch response
    recv = session.last_recv

    # Initialize our extracted parameters
    seq_num = 0
    req_id = 0
    sc_id = 0
    sc_token = 0
    req_hdl = 0
    id_num = 0
    monitored_item_id = []

    # Create our request helper
    request = BlockHelper(node)

    # Parse the message header
    if len(recv) >= 8:
        try:
            # Parse message chunk
            message = MessageChunk.from_binary(SecurityPolicy(), ua.utils.Buffer(recv))

            # Make sure it is a Message in a single chunk
            if (
                message.MessageHeader.MessageType == b"MSG"
                and message.MessageHeader.ChunkType == b"F"
            ):
                # Extract sequence number and compute next sequence number from this.
                seq_num = message.SequenceHeader.SequenceNumber + 1

            # Use python-opcua to parse the CreateSubscriptionResponse response :)
            cs_resp = struct_from_binary(
                ua.CreateMonitoredItemsResponse, ua.utils.Buffer(message.Body)
            )

            # Save secure channel ID.
            sc_id = message.MessageHeader.ChannelId

            # Save token ID.
            sc_token = message.SecurityHeader.TokenId

            # Save request ID.
            req_id = message.SequenceHeader.RequestId + 1

            # Save request handle.
            req_hdl = cs_resp.ResponseHeader.RequestHandle + 1

            # Save and get Identifier Numeric for next RequestHeader.
            id_num = session.id_num

            # Save and get MonitoredItemId
            size = len(cs_resp.Results)
            for i in range(size):
                monitored_item_id.append(cs_resp.Results[i].MonitoredItemId)

            # CreateSubscriptionResponse response successfully parsed
            logger.log_info(
                f"CreateSubscriptionResponse response found: id={sc_id:x}, token={sc_token:x}"
            )
            logger.log_info("Updating Next Request parameters accordingly.")

            # Propagate the values in the next request header
            request.get("c-body").set("sc_id", sc_id)
            request.get("c-body").set("sc_token", sc_token)
            request.get("c-body").set("seq_num", seq_num)
            request.get("c-body").set("req_id", req_id)
            request.get("c-body").set("req_hdl", req_hdl)
            request.get("c-body").set("id_num", id_num)

            # Save monitored item ID in our session.
            session.monitored_item_id = monitored_item_id

            try:  # Publish
                repeat_block = request.get("c-body").get("subs_acknowledgement").get("subs_acknowledgements")
                size = repeat_block.size()
                for i in range(size):
                    repeat_block.set_array_item(i, "subs_id", session.subs_id)
            except Exception as error:
                pass

        except ValueError as valerr:
            logger.log_error("CreateSubscriptionResponse response not found")
            raise FuzzowskiTestCaseAborted(
                "An error occurred while unpacking OPCUA message."
            ) from valerr
        except Exception as error:
            raise FuzzowskiTestCaseAborted() from error
    else:
        raise FuzzowskiTestCaseAborted()


def modify_monitor_to_delete_monitor(
    target: ITargetConnection,
    logger: IFuzzLogger,
    session: OPCUASession,
    node: Request,
    *_,
    **__,
):
    """Callback function called to update the DeleteMonitorItems request fields
    following an ModifyMonitoredItemsResponse response.

    :param target: Fuzzing target
    :param logger: Fuzzer logger
    :param session: Current fuzzing session
    :param node: Next request to send as defined in Fuzzowski
    """

    # Fetch response
    recv = session.last_recv

    # Initialize our extracted parameters
    seq_num = 0
    req_id = 0
    sc_id = 0
    sc_token = 0
    req_hdl = 0
    id_num = 0
    subs_id = 0

    # Create our request helper
    request = BlockHelper(node)

    # Parse the message header
    if len(recv) >= 8:
        try:
            # Parse message chunk
            message = MessageChunk.from_binary(SecurityPolicy(), ua.utils.Buffer(recv))

            # Make sure it is a Message in a single chunk
            if (
                message.MessageHeader.MessageType == b"MSG"
                and message.MessageHeader.ChunkType == b"F"
            ):
                # Extract sequence number and compute next sequence number from this.
                seq_num = message.SequenceHeader.SequenceNumber + 1

            mmi_resp = struct_from_binary(
                ua.ModifyMonitoredItemsResponse, ua.utils.Buffer(message.Body)
            )

            # Save secure channel ID.
            sc_id = message.MessageHeader.ChannelId

            # Save token ID.
            sc_token = message.SecurityHeader.TokenId

            # Save request ID.
            req_id = message.SequenceHeader.RequestId + 1

            # Save request handle.
            req_hdl = mmi_resp.ResponseHeader.RequestHandle + 1

            # Save and get Identifier Numeric for next RequestHeader.
            id_num = session.id_num

            # Save Subscription ID.
            subs_id = session.subs_id

            # ModifyMonitoredItemsResponse response successfully parsed
            logger.log_info(
                f"ModifyMonitoredItemsResponse response found: id={sc_id:x}, token={sc_token:x}"
            )
            logger.log_info("Updating Next Request parameters accordingly.")

            # Propagate the values in the next request header
            request.get("c-body").set("sc_id", sc_id)
            request.get("c-body").set("sc_token", sc_token)
            request.get("c-body").set("seq_num", seq_num)
            request.get("c-body").set("req_id", req_id)
            request.get("c-body").set("req_hdl", req_hdl)
            request.get("c-body").set("id_num", id_num)
            request.get("c-body").set("subs_id", subs_id)

        except ValueError as valerr:
            logger.log_error("ModifyMonitoredItemsResponse response not found")
            raise FuzzowskiTestCaseAborted(
                "An error occurred while unpacking OPCUA message."
            ) from valerr
        except Exception as error:
            raise FuzzowskiTestCaseAborted() from error
    else:
        raise FuzzowskiTestCaseAborted()
