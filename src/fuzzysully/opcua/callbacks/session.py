"""Callbacks for Session related requests
"""

import random

# Imports from asyncua
from asyncua import ua
from asyncua.common.connection import MessageChunk
from asyncua.ua.ua_binary import struct_from_binary
from asyncua.ua.uaprotocol_hand import SecurityPolicy
# Imports from fuzzowski
from fuzzowski import ITargetConnection, IFuzzLogger, Request
from fuzzowski.exception import FuzzowskiTestCaseAborted
# Imports some of our helpers
from ..helpers import generate_node_id, NODE_CLASS
from ...helpers import BlockHelper, OPCUASession


def create_session_to_activate_session(
    target: ITargetConnection,
    logger: IFuzzLogger,
    session: OPCUASession,
    node: Request,
    *_,
    **__,
):
    """Callback function called to update the ActivateSession request fields
    following an CreateSession response.

    :param target: Fuzzing target
    :param logger: Fuzzer logger
    :param session: Current fuzzing session
    :param node: Next request to send as defined in Fuzzowski
    """

    # Fetch response
    recv = session.last_recv
    send = session.last_send

    # Initialize our extracted parameters
    seq_num = 0
    req_id = 0
    sc_id = 0
    sc_token = 0
    req_hdl = 0
    id_num = 0

    # Create our request helper
    request = BlockHelper(node)

    # Parse the message header
    if len(recv) >= 8:
        try:
            # Parse message chunk
            message = MessageChunk.from_binary(SecurityPolicy(), ua.utils.Buffer(recv))
            message_send = MessageChunk.from_binary(SecurityPolicy(), ua.utils.Buffer(send))

            # Make sure it is a Message in a single chunk
            if (
                message.MessageHeader.MessageType == b"MSG"
                and message.MessageHeader.ChunkType == b"F"
            ):
                # Extract sequence number and compute next sequence number from this.
                seq_num = message_send.SequenceHeader.SequenceNumber + 1

            # Use python-opcua to parse the CreateSession response :)
            cs_resp = struct_from_binary(
                ua.CreateSessionResponse, ua.utils.Buffer(message.Body)
            )

            # Save secure channel ID.
            sc_id = message.MessageHeader.ChannelId

            # Save token ID.
            sc_token = message.SecurityHeader.TokenId

            # Save request ID.
            req_id = message.SequenceHeader.RequestId + 1

            # Save request handle.
            req_hdl = cs_resp.ResponseHeader.RequestHandle + 1

            # Save Identifier Numeric for next RequestHeader.
            id_num = cs_resp.Parameters.AuthenticationToken.Identifier

            # CreateSessionResponse response successfully parsed
            logger.log_info(
                f"CreateSessionResponse response found: id={sc_id:x}, token={sc_token:x}"
            )
            logger.log_info("Updating Next Request parameters accordingly.")

            # Propagate the values in the next request header
            request.get("c-body").set("sc_id", sc_id)
            request.get("c-body").set("sc_token", sc_token)
            request.get("c-body").set("seq_num", seq_num)
            request.get("c-body").set("req_id", req_id)
            request.get("c-body").set("req_hdl", req_hdl)
            request.get("c-body").set("id_num", id_num)

            # Save session id into our session
            session.id_num = id_num

        except ua.utils.NotEnoughData:
            try:
                # Use python-opcua to parse response as a ServiceFault
                cs_resp: ua.ServiceFault = struct_from_binary(
                    ua.ServiceFault, ua.utils.Buffer(message.Body)
                )
                err_code = cs_resp.ResponseHeader.ServiceResult.value
                logger.log_warn(f"ServiceFault with code 0x{err_code:x}")
            except Exception as unk_parse:
                raise FuzzowskiTestCaseAborted() from unk_parse
        except ValueError as valerr:
            logger.log_error("CreateSessionResponse response not found")
            raise FuzzowskiTestCaseAborted(
                "An error occurred while unpacking OPCUA message."
            ) from valerr
        except Exception as error:
            raise FuzzowskiTestCaseAborted() from error
    else:
        raise FuzzowskiTestCaseAborted()


def general_body_cb(
    target: ITargetConnection,
    logger: IFuzzLogger,
    session: OPCUASession,
    node: Request,
    request: BlockHelper = None,
    *_,
    **__,
):
    """Callback function called to update the Any request fields
    following an ActivateSessionResponse response (only handle
    body of the request).

    :param target: Fuzzing target
    :param logger: Fuzzer logger
    :param session: Current fuzzing session
    :param node: Next request to send as defined in Fuzzowski
    :param request: the current block helper object  if already created
    """
    if request is None:
        request = BlockHelper(node)
    try:  # Read
        repeat_block = request.get("c-body").get("nodes_to_read").get("read_value_ids")
        size = repeat_block.size()
        for i in range(size):
            repeat_block.set_array_item(i, "node_id", generate_node_id())
    except Exception as error:
        pass

    try:  # HistoryRead
        request.get("c-body").set("extension_id", generate_node_id())
        repeat_block = request.get("c-body").get("nodes_to_read").get("read_value_ids")
        size = repeat_block.size()
        for i in range(size):
            repeat_block.set_array_item(i, "node_id", generate_node_id())
    except Exception as error:
        pass

    try:  # Browse
        repeat_block = (
            request.get("c-body").get("nodes_to_browse").get("browse_description")
        )
        size = repeat_block.size()
        for i in range(size):
            repeat_block.set_array_item(i, "node_id", generate_node_id())
            repeat_block.set_array_item(i, "ref_type_id", generate_node_id())
    except Exception as error:
        pass

    try:  # RegisterNodes
        repeat_block = request.get("c-body").get("register_node_ids")
        size = repeat_block.size()
        for i in range(size):
            repeat_block.set_array_item(i, "node_id", generate_node_id())
    except ValueError as error:
        pass

    try:  # UnregisterNodes
        repeat_block = request.get("c-body").get("unregister_node_ids")
        size = repeat_block.size()
        for i in range(size):
            repeat_block.set_array_item(i, "node_id", generate_node_id())
    except ValueError as error:
        pass

    try:  # AddNode
        repeat_block = request.get("c-body").get("nodes_to_add").get("add_nodes_item")
        size = repeat_block.size()
        for i in range(size):
            repeat_block.set_array_item(i, "parent_node_id", generate_node_id())
            repeat_block.set_array_item(i, "ref_type_id", generate_node_id())
            repeat_block.set_array_item(i, "request_new_node_id", generate_node_id())
            repeat_block.set_array_item(i, "extension_id", generate_node_id())
            repeat_block.set_array_item(i, "node_class", random.choice(NODE_CLASS))
            repeat_block.set_array_item(i, "type_definition", generate_node_id())
    except Exception as error:
        pass

    try:  # TranslateBrowsePathsToNodeIds
        repeat_block = request.get("c-body").get("browse_path").get("browse_paths")
        size = repeat_block.size()
        for i in range(size):
            repeat_block.set_array_item(i, "starting_node", generate_node_id())
            ref_type_id_dic = {}
            size_elements = repeat_block.get("elements").size()
            for j in range(size_elements):
                ref_type_id_dic.update({j: {"reference_type_id": generate_node_id()}})
            repeat_block.set_array_item(i, "elements", ref_type_id_dic)
    except Exception as error:
        pass

    try:  # RegisterServer2
        request.get("c-body").set("extension_id", generate_node_id())
    except Exception as error:
        pass


def activate_to_any(
    target: ITargetConnection,
    logger: IFuzzLogger,
    session: OPCUASession,
    node: Request,
    *_,
    **__,
):
    """Callback function called to update the Any request fields
    following an ActivateSessionResponse response.

    :param target: Fuzzing target
    :param logger: Fuzzer logger
    :param session: Current fuzzing session
    :param node: Next request to send as defined in Fuzzowski
    """

    # Fetch response
    recv = session.last_recv
    send = session.last_send   

    # Initialize our extracted parameters
    seq_num = 0
    req_id = 0
    sc_id = 0
    sc_token = 0
    req_hdl = 0
    id_num = 0

    # Create our request helper
    request = BlockHelper(node)

    # Parse the message header
    if len(recv) >= 8:
        try:
            # Parse message chunk
            message = MessageChunk.from_binary(SecurityPolicy(), ua.utils.Buffer(recv))
            message_send = MessageChunk.from_binary(SecurityPolicy(), ua.utils.Buffer(send))

            # Make sure it is a Message in a single chunk
            if (
                message.MessageHeader.MessageType == b"MSG"
                and message.MessageHeader.ChunkType == b"F"
            ):
                # Extract sequence number and compute next sequence number from this.
                seq_num = message_send.SequenceHeader.SequenceNumber + 1

            # Use python-opcua to parse the ActivateSessionResponse response :)
            as_resp = struct_from_binary(
                ua.ActivateSessionResponse, ua.utils.Buffer(message.Body)
            )

            # Save secure channel ID.
            sc_id = message.MessageHeader.ChannelId

            # Save token ID.
            sc_token = message.SecurityHeader.TokenId

            # Save request ID.
            req_id = message.SequenceHeader.RequestId + 1

            # Save request handle.
            req_hdl = as_resp.ResponseHeader.RequestHandle + 1

            # Save and get Identifier Numeric for next RequestHeader.
            id_num = session.id_num

            # ActivateSessionResponse response successfully parsed
            logger.log_info(
                f"ActivateSessionResponse response found: id={sc_id:x}, token={sc_token:x}"
            )
            logger.log_info("Updating Next Request parameters accordingly.")

            # Propagate the values in the next request header
            request.get("c-body").set("sc_id", sc_id)
            request.get("c-body").set("sc_token", sc_token)
            request.get("c-body").set("seq_num", seq_num)
            request.get("c-body").set("req_id", req_id)
            request.get("c-body").set("req_hdl", req_hdl)
            request.get("c-body").set("id_num", id_num)

            general_body_cb(target, logger, session, node, request)
        except ValueError as valerr:
            logger.log_error("ActivateSessionResponse response not found")
            raise FuzzowskiTestCaseAborted(
                "An error occurred while unpacking OPCUA message."
            ) from valerr
        except Exception as error:
            raise FuzzowskiTestCaseAborted() from error
    else:
        raise FuzzowskiTestCaseAborted()


def any_to_close_session(
    target: ITargetConnection,
    logger: IFuzzLogger,
    session: OPCUASession,
    node: Request,
    *_,
    **__,
):
    """Callback function called to update the CloseSecureChannel request fields
    following a CloseSession.

    :param target: Fuzzing target
    :param logger: Fuzzer logger
    :param session: Current fuzzing session
    :param node: Next request to send as defined in Fuzzowski
    """

    # Fetch response
    recv = session.last_recv
    send = session.last_send
    
    # Initialize our extracted parameters
    seq_num = 0
    req_id = 0
    sc_id = 0
    sc_token = 0

    # Create our request helper
    request = BlockHelper(node)

    # Parse the message header
    if len(recv) >= 8:
        try:
            # Parse message chunk
            message = MessageChunk.from_binary(SecurityPolicy(), ua.utils.Buffer(recv))
            message_send = MessageChunk.from_binary(SecurityPolicy(), ua.utils.Buffer(send))

            # Make sure it is a Message in a single chunk
            if (
                message.MessageHeader.MessageType == b"MSG"
                and message.MessageHeader.ChunkType == b"F"
            ):
                # Extract sequence number and compute next sequence number from this.
                seq_num = message_send.SequenceHeader.SequenceNumber + 1

            # Save secure channel ID.
            sc_id = message.MessageHeader.ChannelId

            # Save token ID.
            sc_token = message.SecurityHeader.TokenId

            # Save request ID.
            req_id = message.SequenceHeader.RequestId + 1

            # Save and get Identifier Numeric for next RequestHeader.
            id_num = session.id_num

            # OpenSecureChannel response successfully parsed
            logger.log_info(f"Any response found: id={sc_id:x}, token={sc_token:x}")
            logger.log_info("Updating CloseSession parameters accordingly.")

            # Propagate the values in the next request header
            request.get("c-body").set("sc_id", sc_id)
            request.get("c-body").set("sc_token", sc_token)
            request.get("c-body").set("seq_num", seq_num)
            request.get("c-body").set("req_id", req_id)
            request.get("c-body").set("id_num", id_num)

        except ua.UaError as ua_err:
            logger.log_error(f"UA error received: {ua_err}")
        except ValueError as valerr:
            logger.log_error("Any response not found")
            raise FuzzowskiTestCaseAborted(
                "An error occurred while unpacking OPCUA message."
            ) from valerr
        except Exception as error:
            raise FuzzowskiTestCaseAborted() from error
    else:
        raise FuzzowskiTestCaseAborted()
