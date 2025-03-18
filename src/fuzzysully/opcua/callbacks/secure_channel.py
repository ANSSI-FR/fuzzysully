"""Callbacks for secure channel related requests
"""

# Imports from asyncua
from asyncua import ua
from asyncua.common.connection import MessageChunk
from asyncua.ua.ua_binary import struct_from_binary
from asyncua.ua.uaprotocol_hand import SecurityPolicy
# Imports from fuzzowski
from fuzzowski import ITargetConnection, IFuzzLogger, Session, Request
from fuzzowski.exception import FuzzowskiTestCaseAborted
# Imports some of our helpers
from ..helpers import generate_node_id
from ...helpers import BlockHelper


def open_channel_to_close_channel(
    target: ITargetConnection,
    logger: IFuzzLogger,
    session: Session,
    node: Request,
    *_,
    **__,
):
    """Callback function called to update the CloseSecureChannel request fields
    following an OpenSecureChannel response.

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

            # Make sure it is a SecureChannel open message in a single chunk
            if (
                message.MessageHeader.MessageType == b"OPN"
                and message.MessageHeader.ChunkType == b"F"
            ):
                # Extract sequence number and compute next sequence number from this.
                seq_num = message_send.SequenceHeader.SequenceNumber + 1

            # Use python-opcua to parse the OpenSecureChannel response :)
            sc_resp = struct_from_binary(
                ua.OpenSecureChannelResponse, ua.utils.Buffer(message.Body)
            )

            req_id = message.SequenceHeader.RequestId + 1

            # Save secure channel ID.
            sc_id = sc_resp.Parameters.SecurityToken.ChannelId

            # Save other parameters as variables.
            sc_token = sc_resp.Parameters.SecurityToken.TokenId

            # OpenSecureChannel response successfully parsed
            logger.log_info(
                f"OpenSecureChannel response found: id={sc_id:x}, token={sc_token:x}"
            )
            logger.log_info("Updating CloseSecureChannel parameters accordingly.")

            # Propagate the values in the next request header
            request.get("c-header").set("sc_id", sc_id)
            request.get("c-body").set("sc_token", sc_token)
            request.get("c-body").set("seq_num", seq_num)
            request.get("c-body").set("req_id", req_id)
            request.get("c-body").set("sc_id2", sc_id)

        except ValueError as valerr:
            logger.log_error("OpenSecureChannel response not found")
            raise FuzzowskiTestCaseAborted(
                "An error occurred while unpacking OPCUA message."
            ) from valerr
        except Exception as error:
            raise FuzzowskiTestCaseAborted() from error
    else:
        raise FuzzowskiTestCaseAborted()


def open_channel_to_any(
    target: ITargetConnection,
    logger: IFuzzLogger,
    session: Session,
    node: Request,
    *_,
    **__,
):
    """Callback function called to update the Next request fields
    following an OpenSecureChannel response.

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


            # Make sure it is a SecureChannel open message in a single chunk
            if (
                message.MessageHeader.MessageType == b"OPN"
                and message.MessageHeader.ChunkType == b"F"
            ):
                # Extract sequence number and compute next sequence number from this.
                seq_num = message_send.SequenceHeader.SequenceNumber + 1

            # Use python-opcua to parse the OpenSecureChannel response :)
            sc_resp = struct_from_binary(
                ua.OpenSecureChannelResponse, ua.utils.Buffer(message.Body)
            )

            # Save secure channel ID.
            sc_id = sc_resp.Parameters.SecurityToken.ChannelId

            # Save token ID.
            sc_token = sc_resp.Parameters.SecurityToken.TokenId

            # Save request ID.
            req_id = message.SequenceHeader.RequestId + 1

            # OpenSecureChannel response successfully parsed
            logger.log_info(
                f"OpenSecureChannel response found: id={sc_id:x}, token={sc_token:x}"
            )
            logger.log_info("Updating Next Request parameters accordingly.")

            # Propagate the values in the next request header
            request.get("c-body").set("sc_id", sc_id)
            request.get("c-body").set("sc_token", sc_token)
            request.get("c-body").set("seq_num", seq_num)
            request.get("c-body").set("req_id", req_id)

            try:  # RegisterServer2
                request.get("c-body").set("extension_id", generate_node_id())
            except Exception as error:
                pass

        except ValueError as valerr:
            logger.log_error("OpenSecureChannel response not found")
            raise FuzzowskiTestCaseAborted(
                "An error occurred while unpacking OPCUA message."
            ) from valerr
        except Exception as error:
            raise FuzzowskiTestCaseAborted() from error
    else:
        raise FuzzowskiTestCaseAborted()


def any_to_close_channel(
    target: ITargetConnection,
    logger: IFuzzLogger,
    session: Session,
    node: Request,
    *_,
    **__,
):
    """Callback function called to update the CloseSecureChannel request fields
    following any response.

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
            # Parse received message chunk
            message = MessageChunk.from_binary(SecurityPolicy(), ua.utils.Buffer(recv))
            
            ## Parse sent message chunk
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

            # OpenSecureChannel response successfully parsed
            logger.log_info(f"Any response found: id={sc_id:x}, token={sc_token:x}")
            logger.log_info("Updating CloseSecureChannel parameters accordingly.")

            # Propagate the values in the next request header
            request.get("c-header").set("sc_id", sc_id)
            request.get("c-body").set("sc_token", sc_token)
            request.get("c-body").set("seq_num", seq_num)
            request.get("c-body").set("req_id", req_id)
            request.get("c-body").set("sc_id2", sc_id)
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
