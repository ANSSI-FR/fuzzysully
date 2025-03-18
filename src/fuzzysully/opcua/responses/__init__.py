"""OPCUA response messages
"""

from struct import unpack, pack
from typing import Mapping

from asyncua import ua
from asyncua.common.connection import MessageChunk
from asyncua.ua.ua_binary import struct_from_binary, DateTime
from asyncua.ua.uaprotocol_hand import SecurityPolicy
from fuzzowski.exception import FuzzowskiRuntimeError
from fuzzowski.responses.response import Response


class ConnProtocolMsgResponse(Response):  # pylint: disable=too-few-public-methods
    """OPCUA Connection Protocol (CP) response message parser."""

    def _extract_variables(self, data: bytes) -> Mapping[str, bytes]:
        """
        Extract variables from an OPCUA Message
        Subclasses must implement this method, from the response, it parses it and returns a dictionary with variables
        and their respective values. All variables set in self.required_vars must be set in this method, or parse()
        will raise a FuzzowskiRuntimeError
        Args:
            data: The response bytes

        Returns: A dictionary with all required variables (and optionally others)
        """
        response_vars = {}

        # Parse Connection Protocol message header (See OPC 10000-6 7.1.2)
        if len(data) >= 8:
            try:
                # Extract values
                msg_type = data[:3]
                reserved = data[3]
                msg_size = unpack("<I", data[4:8])[0]

                # Make sure message type is valid
                if msg_type in [b"HEL", b"ACK", b"ERR", b"RHE"] and reserved == 0x46:
                    response_vars["msg_type"] = msg_type
                    response_vars["msg_size"] = msg_size
            except Exception as error:
                raise FuzzowskiRuntimeError() from error
        else:
            raise FuzzowskiRuntimeError()
        return response_vars


class OpenSecureChannelResponse(Response):  # pylint: disable=too-few-public-methods
    """OPCUA OpenSecureChannel response message.

    We extract from this message the following information:

    - the request id (req_id)
    - the sequence number (seq_num)
    - the secure channel ID (sc_id)
    - the secure channel token ID (sc_token)
    - the revised lifetime (sc_lifetime)
    - the server nonce (server_nonce)
    """

    def _extract_variables(self, data: bytes) -> Mapping[str, bytes]:
        """Parse an OpenSecureChannel response, including different headers."""
        response_vars = {}

        # Parse the message header
        if len(data) >= 8:
            try:

                # Parse message chunk
                message = MessageChunk.from_binary(
                    SecurityPolicy(), ua.utils.Buffer(data)
                )

                # Make sure it is a SecureChannel open message in a single chunk
                if (
                    message.MessageHeader.MessageType == b"OPN"
                    and message.MessageHeader.ChunkType == b"F"
                ):
                    # Extract sequence number and compute next sequence number from this.
                    response_vars["seq_num"] = pack(
                        "<I", message.SequenceHeader.SequenceNumber + 1
                    )

                    # Use python-opcua to parse the OpenSecureChannel response :)
                    sc_resp = struct_from_binary(
                        ua.OpenSecureChannelResponse, ua.utils.Buffer(message.Body)
                    )
                    response_vars["req_id"] = pack(
                        "<I", sc_resp.ResponseHeader.RequestHandle + 1
                    )
                    response_vars["req_id_"] = response_vars["req_id"]

                    # Save secure channel ID.
                    response_vars["sc_id"] = pack(
                        "<I", sc_resp.Parameters.SecurityToken.ChannelId
                    )

                    # Save a copy of secure channel ID as required by the CloseSecureChannel request.
                    response_vars["sc_id2"] = response_vars["sc_id"]

                    # Save other parameters as variables.
                    response_vars["sc_token"] = pack(
                        "<I", sc_resp.Parameters.SecurityToken.TokenId
                    )
                    response_vars["sc_created_at"] = DateTime.pack(
                        sc_resp.Parameters.SecurityToken.CreatedAt
                    )
                    response_vars["sc_lifetime"] = pack(
                        "<I", sc_resp.Parameters.SecurityToken.RevisedLifetime
                    )
                    if sc_resp.Parameters.ServerNonce is None:
                        response_vars["server_nonce"] = b""
                    else:
                        response_vars["serv_nonce"] = sc_resp.Parameters.ServerNonce
            except ValueError as valerr:
                raise FuzzowskiRuntimeError(
                    "An error occurred while unpacking OPCUA message."
                ) from valerr
            except Exception as error:
                raise FuzzowskiRuntimeError() from error
        else:
            raise FuzzowskiRuntimeError()

        return response_vars
