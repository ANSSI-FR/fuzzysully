"""OPCUA server monitors

We are using a Hello message to monitor the target process and check if it is
still active. If the server answers with an ACK or an error message, the server
is working as expected and still processes input. If no valid answer is received,
then we notify a suspect behavior.
"""

from struct import pack, unpack
from time import sleep

from fuzzowski.connections import ITargetConnection
from fuzzowski.monitors.imonitor import IMonitor
from fuzzysully.opcua import OpcuaGlobalParams
from fuzzysully.opcua.connection import OpcuaConnection

# Codes extracted from https://github.com/OPCFoundation/UA-Nodeset/blob/UA-1.05.03-2023-12-15/Schema/StatusCode.csv
OPCUA_STATUS_CODES = [
    0x00000000,
    0x40000000,
    0x80000000,
    0x80010000,
    0x80020000,
    0x80030000,
    0x80040000,
    0x80050000,
    0x80060000,
    0x80070000,
    0x80080000,
    0x80B80000,
    0x80B90000,
    0x80090000,
    0x800A0000,
    0x800B0000,
    0x800C0000,
    0x800D0000,
    0x800E0000,
    0x800F0000,
    0x80100000,
    0x80DB0000,
    0x80110000,
    0x80120000,
    0x80130000,
    0x81140000,
    0x80140000,
    0x80150000,
    0x80160000,
    0x80170000,
    0x80180000,
    0x80190000,
    0x801A0000,
    0x801B0000,
    0x801C0000,
    0x801D0000,
    0x801E0000,
    0x810D0000,
    0x801F0000,
    0x80200000,
    0x80210000,
    0x80220000,
    0x80230000,
    0x80240000,
    0x80250000,
    0x80260000,
    0x80270000,
    0x80280000,
    0x802A0000,
    0x802B0000,
    0x802C0000,
    0x80E50000,
    0x810E0000,
    0x810F0000,
    0x81100000,
    0x80EE0000,
    0x00EF0000,
    0x002D0000,
    0x002E0000,
    0x002F0000,
    0x00300000,
    0x80310000,
    0x80320000,
    0x80330000,
    0x80340000,
    0x80350000,
    0x80360000,
    0x80370000,
    0x80EA0000,
    0x80380000,
    0x80390000,
    0x803A0000,
    0x803B0000,
    0x803C0000,
    0x803D0000,
    0x803E0000,
    0x803F0000,
    0x80400000,
    0x80410000,
    0x80420000,
    0x80430000,
    0x80440000,
    0x80450000,
    0x80460000,
    0x80470000,
    0x80480000,
    0x80C10000,
    0x80C20000,
    0x80C30000,
    0x80490000,
    0x80C40000,
    0x80C50000,
    0x804A0000,
    0x804B0000,
    0x804C0000,
    0x804D0000,
    0x804E0000,
    0x81120000,
    0x80ED0000,
    0x80F00000,
    0x804F0000,
    0x80500000,
    0x80510000,
    0x80520000,
    0x80530000,
    0x80540000,
    0x80550000,
    0x80560000,
    0x80570000,
    0x80580000,
    0x80590000,
    0x80C60000,
    0x805A0000,
    0x805B0000,
    0x805C0000,
    0x805D0000,
    0x805E0000,
    0x805F0000,
    0x80600000,
    0x80610000,
    0x80620000,
    0x80630000,
    0x80640000,
    0x80650000,
    0x80660000,
    0x80670000,
    0x80680000,
    0x80690000,
    0x40BC0000,
    0x806A0000,
    0x806B0000,
    0x80C90000,
    0x80CA0000,
    0x80CB0000,
    0x40C00000,
    0x00BA0000,
    0x80C80000,
    0x406C0000,
    0x806D0000,
    0x806E0000,
    0x806F0000,
    0x80700000,
    0x80E60000,
    0x80710000,
    0x80720000,
    0x80BD0000,
    0x80730000,
    0x80740000,
    0x80750000,
    0x80760000,
    0x81110000,
    0x80770000,
    0x80780000,
    0x80790000,
    0x807A0000,
    0x00DF0000,
    0x807B0000,
    0x807C0000,
    0x80BF0000,
    0x81150000,
    0x807D0000,
    0x807E0000,
    0x807F0000,
    0x80800000,
    0x80810000,
    0x80820000,
    0x80830000,
    0x80840000,
    0x80850000,
    0x80860000,
    0x80870000,
    0x80880000,
    0x80BE0000,
    0x80890000,
    0x808A0000,
    0x808B0000,
    0x808C0000,
    0x808D0000,
    0x808E0000,
    0x408F0000,
    0x40900000,
    0x40910000,
    0x40920000,
    0x40930000,
    0x40940000,
    0x40950000,
    0x00960000,
    0x00EB0000,
    0x80970000,
    0x80980000,
    0x80CC0000,
    0x80990000,
    0x809A0000,
    0x80BB0000,
    0x80CD0000,
    0x80CE0000,
    0x80CF0000,
    0x80D00000,
    0x80D10000,
    0x80D20000,
    0x80D30000,
    0x809B0000,
    0x80D70000,
    0x80D80000,
    0x809D0000,
    0x809E0000,
    0x809F0000,
    0x80A00000,
    0x80A10000,
    0x00A20000,
    0x00A30000,
    0x40A40000,
    0x00A50000,
    0x00A60000,
    0x80D40000,
    0x80D50000,
    0x80D60000,
    0x80DA0000,
    0x00D90000,
    0x80E40000,
    0x81130000,
    0x80E80000,
    0x811F0000,
    0x81200000,
    0x80E90000,
    0x80EC0000,
    0x00DC0000,
    0x00DD0000,
    0x40DE0000,
    0x00E00000,
    0x80E10000,
    0x40E20000,
    0x80E30000,
    0x01160000,
    0x01170000,
    0x01180000,
    0x81190000,
    0x811A0000,
    0x811B0000,
    0x811C0000,
    0x811D0000,
    0x811E0000,
    0x00A70000,
    0x00A80000,
    0x00A90000,
    0x00AA0000,
    0x80AB0000,
    0x80AC0000,
    0x80AD0000,
    0x80AE0000,
    0x80AF0000,
    0x80B00000,
    0x80B10000,
    0x80B20000,
    0x80B30000,
    0x80B40000,
    0x80B50000,
    0x80B60000,
    0x80B70000,
    0x42080000,
    0x42090000,
    0x420A0000,
    0x420F0000,
    0x04010000,
    0x04020000,
    0x04030000,
    0x04040000,
    0x04070000,
    0x04080000,
    0x04090000,
    0x80E70000,
]


class OPCUAMonitor(IMonitor):
    """
    OPCUA monitor module interface
    @Author: dcauquil

    Based on OPCUA specification OPC 10000-6 section 7.1.2.3 (Hello Message)
    """

    @staticmethod
    def name() -> str:
        """Return the monitor name that will be displayed in Fuzzowski"""
        return "OPCUAMon"

    @staticmethod
    def help() -> str:
        """Return a help message associated with this monitor"""
        return "Sends a Hello message and check if the remote server answers."

    def test(self) -> bool:
        """This is the function that has the main functionality of the monitor.
        When this function returns False, the actual Test Case is added as a
        Suspect.

        Returns: True if everything is OK. False if the monitor failed
        """
        conn = self.get_connection_copy()
        result = self._send_hello(conn)
        return result

    def _send_hello(self, conn: ITargetConnection):
        """Send an OPCUA Hello message in the current connection and check the
        answer sent by the server, if any.
        """

        # Craft our Hello message
        opcua_hello_message_body = (
            b"\x00\x00\x00\x00"  # Protocol version
            b"\x00\x20\x00\x00"  # ReceiveBufferSize = 8192 bytes (little endian)
            b"\x00\x20\x00\x00"  # SendBufferSize = 8192 bytes (little endian)
            b"\x00\x00\x00\x00"  # Client has no message size limit for MaxMessageSize
            b"\x00\x00\x00\x00"  # Client has no chunk number limit for MaxChunkCount
            + pack("<I", len(OpcuaGlobalParams.get_endpoint()))
            + OpcuaGlobalParams.get_endpoint()
        )

        opcua_hello_message_header = (
            b"HEL"  # MessageType = HEL
            b"F"  # Reserved, must be 'F'
            + pack(
                "<I", len(opcua_hello_message_body) + 8
            )  # Message length, including header
        )

        opcua_hello_message = opcua_hello_message_header + opcua_hello_message_body

        # Try to send it to the target OPCUA server
        try:
            # Start a new connection to the OPCUA server.
            conn.open()

            # Send a valid Hello message.
            conn.send(opcua_hello_message)

            # Wait for an answer.
            data = conn.recv_all(10000)

            # Validate this answer (if any).
            if len(data) == 0:
                # No answer, unexpected behavior !
                self.logger.log_error(
                    "OPCUA error response, getting an answer"
                    " to a Hello message failed !"
                )
                result = False
            else:
                # First, retrieve the message type field and check
                # if we got an ACK message.
                msg_type = data[:3]
                if msg_type == b"ACK":
                    # Check ACK message size (must be 28).
                    msg_size = unpack("<I", data[4:8])[0]
                    result = msg_size == 28
                    if not result:
                        self.logger.log_error(
                            f"OPCUA ACK message has wrong size ({msg_size} instead of 28)"
                        )
                elif msg_type == b"ERR":
                    # Check error message code (must be one of the known
                    # status codes).
                    err_code = unpack("<I", data[8:12])
                    result = err_code in OPCUA_STATUS_CODES
                    if not result:
                        self.logger.log_error(
                            f"Unknown OPCUA error code: 0x{err_code:X}"
                        )
                else:
                    self.logger.log_error(
                        f"Unknown OPCUA message type received: {msg_type}"
                    )
                    result = False
        except Exception as e:
            # An unexpected exception occurred, log it.
            self.logger.log_error(
                f"OPCUA error response, sending Hello message failed !! Exception while receiving: \
{type(e).__name__}. {str(e)}"
            )
            result = False
        finally:
            conn.close()

        return result


class OPCUAClientMonitor(IMonitor):
    """
    OPCUA asyncua-based client monitor

    This monitor relies on our OPCUAConnection class to initiate a connection
    to the target server, create a secure channel and then a session, and
    eventually activate it. If everything works fine, the target server
    is considered active.
    """

    @staticmethod
    def name() -> str:
        """Return the monitor name that will be displayed in Fuzzowski"""
        return "OPCUAClientMonitor"

    @staticmethod
    def help() -> str:
        """Return a help message associated with this monitor"""
        return "Create an OPCUA session and check if server answers.."

    def test(self) -> bool:
        """This is the function that has the main functionality of the monitor.
        When this function returns False, the actual Test Case is added as a
        Suspect.

        Returns: True if everything is OK. False if the monitor failed
        """
        conn = self.get_connection_copy()
        result = self.check_session(conn)
        return result

    def get_connection_copy(self):
        """Override the way IMonitor copy its connection as Asyncua OPC client
        cannot be deep-copied. We need to create a new connection with the same
        parameters as the one used for fuzzing.
        """
        # Access our target active connection object
        active_conn = self.session.target.target_connection

        # Create a new connection with same parameters
        conn = OpcuaConnection(
            active_conn.host,
            active_conn.port,
            active_conn.d_path,
            active_conn.app_uri,
            active_conn.timeout,
            active_conn.username,
            active_conn.password,
        )

        # Duplicate security parameter if required
        if active_conn.security is not None:
            conn.security = active_conn.security

        # Return this new connection
        return conn

    def check_session(self, conn: ITargetConnection):
        """Simply create an OPCUA connection with session creation through
        asyncua.
        """
        result = False

        try:
            # Start a new connection to the OPCUA server, create a secure channel,
            # create a session and activate it.
            conn.open()

            # Close connection.
            conn.close()

            # If everything goes as expected, server is correctly answering.
            result = True
        except Exception:
            self.logger.log_error("Unable to create a session on the target server ! ")
            result = False

        # Return result
        return result


class OPCUAMonitorReverse(IMonitor):
    """
    OPCUA monitor module interface for reverse connection
    @Author: dcauquil

    Based on OPCUA specification OPC 10000-6 section 7.1.2.3 (Reverse Hello Message)
    """

    @staticmethod
    def name() -> str:
        """Return the monitor name that will be displayed in Fuzzowski"""
        return "OPCUAMonReverse"

    @staticmethod
    def help() -> str:
        """Return a help message associated with this monitor"""
        return "Sends a ReverseHello message and check if the remote client answers."

    def test(self) -> bool:
        """This is the function that has the main functionality of the monitor.
        When this function returns False, the actual Test Case is added as a
        Suspect.

        Returns: True if everything is OK. False if the monitor failed
        """
        conn = self.get_connection_copy()
        result = self._send_reverse_hello(conn)
        return result

    def _send_reverse_hello(self, conn: ITargetConnection):
        """Send an OPCUA Hello message in the current connection and check the
        answer sent by the server, if any.
        """
        result = False

        # Craft a valid ReverseHello message
        app_uri = OpcuaGlobalParams.get_app_uri()
        endpoint_uri = OpcuaGlobalParams.get_endpoint()

        # Make sure app_uri and endpoint_uri are bytes
        if isinstance(app_uri, str):
            app_uri = app_uri.encode("utf-8")
        if isinstance(endpoint_uri, str):
            endpoint_uri = endpoint_uri.encode("utf-8")

        opcua_reverse_hello_message_body = (
            pack("<I", len(app_uri))
            + app_uri
            + pack("<I", len(endpoint_uri))
            + endpoint_uri
        )
        opcua_reverse_hello_message_header = (
            b"RHE"  # MessageType = HEL
            b"F"  # Reserved, must be 'F'
            + pack("<I", len(opcua_reverse_hello_message_body) + 8)  # Message length
        )

        opcua_reverse_hello_message = (
            opcua_reverse_hello_message_header + opcua_reverse_hello_message_body
        )

        try:
            # We need to wait at least 1 second to make sure our client has
            # closed the previous connection and is listening again.
            sleep(1)

            # Start a new connection to the OPCUA server.
            conn.open()

            # Send a valid Hello message.
            conn.send(opcua_reverse_hello_message)

            # Wait for an answer.
            data = conn.recv_all(10000)

            # Validate this answer (if any).
            if len(data) == 0:
                # No answer, unexpected behavior !
                self.logger.log_error(
                    "OPCUA error response, getting an answer"
                    " to a ReverseHello message failed !"
                )
                result = False
            else:
                # First, retrieve the message type field and check
                # if we got an HELLO message.
                msg_type = data[:3]
                if msg_type != b"HEL" or data[3] == b"F":
                    result = False
                else:
                    result = True
        except Exception as e:
            self.logger.log_error(e)
            # An unexpected exception occurred, log it.
            self.logger.log_error(
                f"OPCUA error response, sending ReverseHello message failed !! \
Exception while receiving: {type(e).__name__}. {str(e)}"
            )
            result = False
        finally:
            conn.close()

        return result
