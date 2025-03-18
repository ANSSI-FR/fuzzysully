"""This module provides the basic OPCUA fuzzing class `FuzzySully`.

When the None security policy is set, `FuzzySully` allows fuzzing
of the message, security and sequence headers in message chunks as well as
some specific OPCUA requests.

This class also uses an OPCUA client from a modified version of `opcua-asyncio`
to support the *Sign* and *SignAndEncrypt* modes (i.e., Basic256Sha256 policy,
with or without encryption). A client certificate and private key must be provided,
as well as the key password (if needed). By default, *Sign* mode is used but
*SignAndEncrypt* mode is possible when the `encrypt` parameter is set to `True`.
"""

from enum import StrEnum
from hashlib import md5
from pathlib import Path

# Local imports
from fuzzowski import SocketConnection, Target
from fuzzysully.fuzzer import OPCUAFuzzer, OPCUAMode
from fuzzysully.opcua import OpcuaGlobalParams
from fuzzysully.opcua.connection import OpcuaConnection
from fuzzysully.opcua.monitors import (
    OPCUAMonitor,
    OPCUAMonitorReverse,
    OPCUAClientMonitor,
)
from .helpers import OPCUASession


class OPCUASupportedPolicies(StrEnum):
    """
    Complete list of policies supported by OPCUA is defined in
    asyncua.client.client.Client.set_security_string:
    " `Policy`` is ``Basic128Rsa15``, ``Basic256`` or ``Basic256Sha256``".
    Fuzzy Sully only support a subset of these.
    """

    NONE = "None"
    BASIC_SHA = "Basic256Sha256"


class FuzzySully:  # pylint: disable=too-few-public-methods
    """
    Global class to handle final fuzzer tool.
    """

    _available_functions = None

    @classmethod
    def list_available_functions(cls, mode: OPCUAMode) -> list[str]:
        """
        This method computes the functions that can be fuzzed with
        FuzzySully for a given mode. It caches the functions to avoid
        useless computation time.
        :param mode: an OPCUA mode
        :return: the list of the available functions
        """
        if cls._available_functions is None:
            cls._available_functions = dict()
            for m in OPCUAMode.__members__.values():
                cls._available_functions[m] = OPCUAFuzzer.get_requests_name(m)
        return cls._available_functions[mode]

    def __init__(
        self,
        mode: OPCUAMode,
        host: str,
        port: int,
        d_path : str="",
        bind: int = 4840,
        send_timeout: float = 5.0,
        recv_timeout: float = 5.0,
        sleep_time: float = 0.0,
        new_conns: bool = False,
        transmit_full_path: bool = False,
        no_recv: bool = False,
        no_recv_fuzz: bool = False,
        check_recv: bool = False,
        crash_threshold_request: int = 9999,
        crash_threshold_element: int = 9999,
        policy: OPCUASupportedPolicies = OPCUASupportedPolicies.NONE,
        client_cert_path: Path = None,
        private_key_path: Path = None,
        private_key_pwd: str = None,
        app_uri: str = "urn:S2OPC:localhost",
        fuzz_requests: list[str] = None,
        encrypt: bool = False,
        username: str = None,
        password: str = None,
    ):
        # Prepare log file name (similar to fuzzowski ones)
        if fuzz_requests:
            reqs = md5(", ".join(fuzz_requests).encode("utf-8")).hexdigest()
        else:
            fuzz_requests = []
            reqs = "all"
        self.session_filename = (
            f"OPCUA_{host}_{port}_{d_path}_TCP_{mode}_{policy}_{reqs}.log".replace("/", ".")
        )

        OpcuaGlobalParams.set_app_uri(app_uri)

        # Defines values that change according to policy/mode
        # monitoring, endpoints, fuzzer and the OPCUA connection
        self.fuzzer = OPCUAFuzzer(mode, fuzz_requests)
        if policy == OPCUASupportedPolicies.NONE:
            if mode == OPCUAMode.REVERSE_MODE:
                # Set endpoint to match our server endpoint
                OpcuaGlobalParams.set_endpoint(
                    f"opc.tcp://{host}:{bind}".encode("utf-8")
                )
                # Use a specific monitoring class
                monitors = [OPCUAMonitorReverse]
            elif mode == OPCUAMode.SERVER:
                # Normal mode, set target endpoint
                OpcuaGlobalParams.set_endpoint(
                    f"opc.tcp://{host}:{port}{d_path}".encode("utf-8")
                )
                # Use the default monitoring class
                monitors = [OPCUAMonitor]
            else:
                raise Exception(
                    f"Fuzzowski does not handle {mode} mode with the policy {policy}."
                )
            is_signed = False
            connection = SocketConnection(
                host,
                port,
                proto="tcp",
                bind=bind,
                send_timeout=send_timeout,
                recv_timeout=recv_timeout,
            )
        else:  # policy is BasicSha
            if mode == OPCUAMode.GDS or mode == OPCUAMode.SERVER:
                monitors = [OPCUAClientMonitor]
            else:
                raise Exception(
                    f"Fuzzowski does not handle {mode} mode with the policy {policy}."
                )

            if client_cert_path is None or private_key_path is None:
                raise Exception(
                    f"{policy} requires to have a client certificate and a private key."
                )

            is_signed = True
            connection = OpcuaConnection(
                host,
                port,
                d_path,
                app_uri=app_uri,
                timeout=send_timeout,
                username=username,
                password=password,
            )
            connection.set_security(
                policy,
                client_cert=client_cert_path,
                key=private_key_path,
                password=private_key_pwd,
                sign=True,
                encrypt=encrypt,
            )
            if mode == OPCUAMode.GDS:
                # We must quickly connect to the GDS to find the method
                # NodeIds before generating our protocol nodes.
                connection.open()
                # Browse root to define gds nodes
                connection.browse_root()

                # And we close the OPCUA connection.
                connection.close()

        # Define all possible nodes for our protocol
        self.fuzzer.define_nodes(mode, is_signed=is_signed)

        # Specify our target
        self.target = Target(connection=connection)

        # Create a fuzzing session
        self.session = OPCUASession(
            session_filename=self.session_filename,
            # connection options
            sleep_time=sleep_time,
            new_connection_between_requests=new_conns,
            transmit_full_path=transmit_full_path,
            # recv options
            receive_data_after_each_request=not no_recv,
            receive_data_after_fuzz=not no_recv_fuzz,
            check_data_received_each_request=check_recv,
            # crashes options
            crash_threshold_request=crash_threshold_request,
            crash_threshold_element=crash_threshold_element,
            # others
            target=self.target,
            restarter=None,
            monitors=monitors,
        )

        # Add requests to our session
        for name, fuzz_method in self.fuzzer.get_requests():
            try:
                if mode == OPCUAMode.SERVER:
                    fuzz_method(
                        s=self.session,
                        is_signed=is_signed,
                    )
                else:
                    fuzz_method(self.session)
            except NotImplementedError:
                self.session.logger.log_warn(
                    f"'{name}' request cannot be fuzzed with the policy {policy}"
                )

    def run(self):
        """Start the session fuzzer!"""
        self.session.start()
