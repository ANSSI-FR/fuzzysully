"""Callbacks for Subscription related requests
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
from ..helpers import generate_node_id
from ...helpers import BlockHelper, OPCUASession


def subscription_to_create_monitor_signed(
    target: ITargetConnection,
    logger: IFuzzLogger,
    session: OPCUASession,
    node: Request,
    request: BlockHelper = None,
    *_,
    **__,
):
    """Callback function called to update the Publish request fields
    following an CreateSubscriptionResponse response, used for signed mode.

    :param target: Fuzzing target
    :param logger: Fuzzer logger
    :param session: Current fuzzing session
    :param node: Next request to send as defined in Fuzzowski
    :param request: the current block helper object if already created
    """
    if request is None:
        request = BlockHelper(node)

    # Subscription id
    subs_id = 0

    # Fetch response
    recv = session.last_recv
    # Parse the message header
    if len(recv) >= 8:
        try:
            # Convert bytes to buffer
            message = ua.utils.Buffer(recv)

            # Use python-opcua to parse the CreateSubscription response :)
            resp = struct_from_binary(ua.CreateSubscriptionResponse, message)

            # Get the Parameter
            resp_param = resp.Parameters

            # Get subscription id from Parameter
            subs_id = resp_param.SubscriptionId

            # Propagate the values in the request
            request.get("c-body").set("subs_id", subs_id)

            # Save subscription ID into our session.
            session.subs_id = subs_id

        except ValueError as valerr:
            logger.log_error("CreateSubscription response not found")
            raise FuzzowskiTestCaseAborted(
                "An error occurred while unpacking OPCUA message."
            ) from valerr
        except Exception as error:
            raise FuzzowskiTestCaseAborted() from error
    else:
        raise FuzzowskiTestCaseAborted()

    try:
        repeat_block = (
            request.get("c-body").get("item_to_create").get("monitor_item_create")
        )
        size = repeat_block.size()
        for i in range(size):
            repeat_block.set_array_item(i, "node_id", generate_node_id())
            repeat_block.set_array_item(i, "extension_id", generate_node_id())
    except ValueError:
        pass


def subscription_to_create_monitor(
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

            # Use python-opcua to parse the CreateSubscriptionResponse response :)
            cs_resp = struct_from_binary(
                ua.CreateSubscriptionResponse, ua.utils.Buffer(message.Body)
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

            # Save Subscription ID.
            subs_id = cs_resp.Parameters.SubscriptionId

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
            request.get("c-body").set("subs_id", subs_id)

            # Save subscription ID into our session.
            session.subs_id = subs_id

        except ValueError as valerr:
            logger.log_error(f"CreateSubscriptionResponse response not found {valerr}")
            raise FuzzowskiTestCaseAborted(
                "An error occurred while unpacking OPCUA message."
            ) from valerr
        except Exception as error:
            raise FuzzowskiTestCaseAborted() from error
    else:
        raise FuzzowskiTestCaseAborted()


def delete_monitor_body(
    target: ITargetConnection,
    logger: IFuzzLogger,
    session: OPCUASession,
    node: Request,
    request: BlockHelper = None,
    *_,
    **__,
):
    """Callback function called to update the DeleteMonitorItems request fields
    of its body.

    :param target: Fuzzing target
    :param logger: Fuzzer logger
    :param session: Current fuzzing session
    :param node: Next request to send as defined in Fuzzowski
    :param request: the current block helper object if already created
    """
    if request is None:
        request = BlockHelper(node)
    # Set subscription id
    request.get("c-body").set("subs_id", session.subs_id)
    # Populate the array of monitored items to delete
    repeat_block = (
        request.get("c-body").get("item_to_delete").get("monitor_item_delete")
    )
    size = repeat_block.size()
    for i in range(size):
        repeat_block.set_array_item(
            i, "monitored_item_id", session.monitored_item_id[i]
        )


def publish_to_delete_monitor(
    target: ITargetConnection,
    logger: IFuzzLogger,
    session: OPCUASession,
    node: Request,
    *_,
    **__,
):
    """Callback function called to update the DeleteMonitorItems request fields
    following an PublishResponse response.

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

            # Use python-opcua to parse the PublishResponse response :)
            cs_resp = struct_from_binary(
                ua.PublishResponse, ua.utils.Buffer(message.Body)
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

            # Save Subscription ID.
            subs_id = cs_resp.Parameters.SubscriptionId

            # PublishResponse response successfully parsed
            logger.log_info(
                f"PublishResponse response found: id={sc_id:x}, token={sc_token:x}"
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

            delete_monitor_body(target, logger, session, node, request)

        except ValueError as valerr:
            logger.log_error("PublishResponse response not found")
            raise FuzzowskiTestCaseAborted(
                "An error occurred while unpacking OPCUA message."
            ) from valerr
        except Exception as error:
            raise FuzzowskiTestCaseAborted() from error
    else:
        raise FuzzowskiTestCaseAborted()


def modify_monitor_body(
    target: ITargetConnection,
    logger: IFuzzLogger,
    session: OPCUASession,
    node: Request,
    request: BlockHelper = None,
    *_,
    **__,
):
    """Callback function called to update the ModifyMonitorItems request fields
    of its body.

    :param target: Fuzzing target
    :param logger: Fuzzer logger
    :param session: Current fuzzing session
    :param node: Next request to send as defined in Fuzzowski
    :param request: the current block helper object if already created
    """
    if request is None:
        request = BlockHelper(node)
    # Set subscription id
    request.get("c-body").set("subs_id", session.subs_id)
    repeat_block = (
        request.get("c-body").get("item_to_modify").get("monitor_item_modify")
    )
    size = repeat_block.size()
    for i in range(size):
        repeat_block.set_array_item(
            i, "monitored_item_id", session.monitored_item_id[i]
        )
        repeat_block.set_array_item(i, "extension_id", generate_node_id())


def publish_to_modify_monitor(
    target: ITargetConnection,
    logger: IFuzzLogger,
    session: OPCUASession,
    node: Request,
    *_,
    **__,
):
    """Callback function called to update the ModifyMonitorItems request fields
    following an PublishResponse response.

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

            # Use python-opcua to parse the PublishResponse response :)
            cs_resp = struct_from_binary(
                ua.PublishResponse, ua.utils.Buffer(message.Body)
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

            # Save Subscription ID.
            subs_id = cs_resp.Parameters.SubscriptionId

            # PublishResponse response successfully parsed
            logger.log_info(
                f"PublishResponse response found: id={sc_id:x}, token={sc_token:x}"
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

            # Populate the array of items to modify
            modify_monitor_body(target, logger, session, node, request)

        except ValueError as valerr:
            logger.log_error("PublishResponse response not found")
            raise FuzzowskiTestCaseAborted(
                "An error occurred while unpacking OPCUA message."
            ) from valerr
        except Exception as error:
            raise FuzzowskiTestCaseAborted() from error
    else:
        raise FuzzowskiTestCaseAborted()
