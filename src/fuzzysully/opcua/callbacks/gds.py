"""Callbacks for GDS related requests
"""

# Imports from asyncua
from asyncua import ua
from asyncua.ua.ua_binary import struct_from_binary

# Imports from fuzzowski
from fuzzowski import ITargetConnection, IFuzzLogger, Request
from fuzzowski.exception import FuzzowskiTestCaseAborted

# Imports some of our helpers
from ..helpers import generate_node_id
from ...helpers import BlockHelper, OPCUASession


def _update_node_id_field(request: BlockHelper, field_names: list[str]) -> None:
    """Update given fields of a 'c-body' block with freshly generated node_ids.

    :param request: Next request to send as defined in Fuzzowski
    :param field_names: List of c-body fields to update
    """

    try:
        for name in field_names:
            # Generate a new node id
            new_node_id = generate_node_id()
            # Propagate the value in the corresponding field
            request.get("c-body").set(name, new_node_id)

    except Exception as error:
        raise FuzzowskiTestCaseAborted() from error


def finish_request_start_signing_request_cb(
    target: ITargetConnection,
    logger: IFuzzLogger,
    session: OPCUASession,
    node: Request,
    *_,
    **__,
):
    """Callback function called to update the FinishRequest fields.

    :param target: Fuzzing target
    :param logger: Fuzzer logger
    :param session: Current fuzzing session
    :param node: Next request to send as defined in Fuzzowski
    """

    # Create our request helper
    request = BlockHelper(node)

    app_num_mutations = (
        request.get("c-body").get("app_id").num_mutations
    )  # APP_ID Total num of mutation
    app_mutant_index = (
        request.get("c-body").get("app_id").mutant_index
    )  # APP_ID Index of current mutation
    req_num_mutations = (
        request.get("c-body").get("request_id").num_mutations
    )  # REQUEST_ID Total num of mutation
    req_mutant_index = (
        request.get("c-body").get("request_id").mutant_index
    )  # REQUEST_ID Index of current mutation

    # This means that the mutant app_id has now finished mutating
    if app_num_mutations == app_mutant_index:
        session.session.time_to_fuzz = True

    # This means that the mutant request_id has now finished mutating
    if req_num_mutations == req_mutant_index:
        session.session.time_to_fuzz = False

    if session.session.time_to_fuzz:
        _update_node_id_field(request, ["request_id"])
    else:
        # Fetch response
        recv = session.last_recv

        # Parse the message header
        if len(recv) >= 8:
            try:
                # Convert bytes to buffer
                message = ua.utils.Buffer(recv)

                # Use python-opcua to parse the Call response :)
                resp = struct_from_binary(ua.CallResponse, message)

                # Get the first Result
                call_result = resp.Results[0]

                # Check if the OutputArguments list is not empty
                if len(call_result.OutputArguments) != 0:

                    # Get the first OutputArgument
                    output_argument = call_result.OutputArguments[0]

                    # Get the request_id from the response
                    req_id = output_argument.Value.to_binary()

                    # Propagate the values in the next request header
                    request.get("c-body").set("request_id", req_id)

                else:
                    _update_node_id_field(request, ["request_id"])

                # ActivateSessionResponse response successfully parsed
                logger.log_info(f"Call response found.")
                logger.log_info("Updating Finish Request parameters accordingly.")

            except ValueError as valerr:
                logger.log_error("Call response not found")
                raise FuzzowskiTestCaseAborted(
                    "An error occurred while unpacking OPCUA message."
                ) from valerr
            except Exception as error:
                raise FuzzowskiTestCaseAborted() from error
        else:
            raise FuzzowskiTestCaseAborted()
