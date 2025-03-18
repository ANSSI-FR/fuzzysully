"""Callback for ReverseHello
"""

# Imports from asyncua

# Imports from fuzzowski
from fuzzowski import ITargetConnection, IFuzzLogger, Request
from fuzzowski.exception import FuzzowskiTestCaseAborted

# Imports some of our helpers
from ...helpers import OPCUASession


def reverse_hello_to_error(
    target: ITargetConnection,
    logger: IFuzzLogger,
    session: OPCUASession,
    node: Request,
    *_,
    **__
):
    """Callback function called to update the Reverse Hello request fields.

    :param target: Fuzzing target
    :param logger: Fuzzer logger
    :param session: Current fuzzing session
    :param node: Next request to send as defined in Fuzzowski
    """
    # Last received data
    recv = session.last_recv

    # An empty response is considered a valid outcome, as client is supposed
    # to close the connection in case it receives a wrong ReverseHello message
    if recv is None or ((recv is not None) and len(recv) == 0):
        raise FuzzowskiTestCaseAborted()

    # If we still get something, make sure it is a valid hello message !
    try:
        # Parse message chunk
        print(recv)
        msg_type = recv[0:3]
        chunk_type = recv[3:4]
        print(chunk_type)

        # Make sure it is a SecureChannel open message in a single chunk
        assert msg_type == b"HEL"
        assert chunk_type == b"F"

    except ValueError as valerr:
        logger.log_error("Unexpected OPCUA message received !")
        raise FuzzowskiTestCaseAborted(
            "An error occurred while unpacking OPCUA message."
        ) from valerr
