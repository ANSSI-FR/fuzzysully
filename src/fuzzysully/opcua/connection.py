"""This module defines the OpcuaConnection class that relies on `opcua-asyncio`
to create a connection with a remote OPCUA server.

Note that we forked `opcua-asyncio` to allow raw UA messages to be sent through
a legitimate OPC TCP connection.
"""

import asyncio
from threading import Lock
from typing import Generator

from asyncua import ua
from asyncua.client import Client
from asyncua.common import Node
from asyncua.ua.ua_binary import struct_from_binary, to_binary
from fuzzowski.exception import (
    FuzzowskiTargetConnectionFailedError,
    FuzzowskiTargetConnectionReset,
)
from . import OpcuaGlobalParams
from .gds import OpcuaNodeId


class OpcuaConnection:
    """This class provides a compatible interface with Fuzzowski ITargetConnection
    but relies on `opcua-async` implementation to handle encryption and signature.

    Since we don't use a socket, we emulate the received buffer based on the
    data we receive after sending a request.
    """

    def __init__(
        self,
        host: str,
        port: int,
        d_path: str,
        app_uri: str = "urn:S2OPC:localhost",
        timeout: float = 5.0,
        username: str = None,
        password: str = None,
    ):
        self.connection: Client = None
        self.timeout = timeout
        self.recv_lock = Lock()
        self.recv_buffer = b""
        self.host = host
        self.port = port
        self.d_path = d_path
        self.url = f"ocp.tcp://{self.host}:{self.port}{self.d_path}"
        self.loop = asyncio.new_event_loop()
        self.app_uri = app_uri
        self.security = None
        self.username = username
        self.password = password

    def close(self):
        """Close the OPCUA client connection."""
        if self.connection is not None:
            # Disconnect our sessionless client.
            self.loop.run_until_complete(self.connection.disconnect())

    def open(self):
        """Open OPCUA connection, send Hello message and create a secure
        channel to send messages."""
        # Create our OPCUA client
        self.connection = Client(self.url, timeout=self.timeout)
        self.connection.application_uri = self.app_uri
        if self.username is not None and self.password is not None:
            self.connection.set_user(self.username)
            self.connection.set_password(self.password)

        # Set security if required
        if self.security is not None:
            # Update connection security
            self.loop.run_until_complete(
                self.connection.set_security_string(self.security)
            )

        # Connect to the remote server
        try:
            # Connect and create session
            self.loop.run_until_complete(self.connection.connect())

        except Exception as err:
            print(err)
            print("error while connecting")
            # Could not connect
            self.connection = None
            raise FuzzowskiTargetConnectionFailedError("ECONNREFUSED") from err

    def browse_node(
        self, node: Node, name: str = None, nodeclass=None
    ) -> Generator[ua.ReferenceDescription, None, None]:
        """Browse a given node and return its subnodes."""
        nodes = self.loop.run_until_complete(self.connection.browse_nodes(nodes=[node]))
        _, root_nodes = nodes[0]
        for desc in root_nodes.References:
            if name is not None:
                if desc.BrowseName.Name == name:
                    yield desc
            elif nodeclass is not None:
                if desc.NodeClass == nodeclass:
                    yield desc
            else:
                yield desc

    def browse_root(self):
        """Browse OPCUA server Root node"""
        gds_methods = [
            "FinishRequest",
            "GetCertificateGroups",
            "GetCertificateStatus",
            "GetTrustList",
            "RevokeCertificate",
            "StartNewKeyPairRequest",
            "StartSigningRequest",
        ]

        # Get root node
        objects_node = self.connection.get_objects_node()

        # Browse root node and search for 'Directory' folder
        directory_node = None
        for node in self.browse_node(objects_node, name="Directory"):
            directory_node = self.connection.get_node(node.NodeId)
            OpcuaGlobalParams.set_gds_directory_nodeid(
                OpcuaNodeId(node.NodeId.NamespaceIndex, node.NodeId.Identifier)
            )
            break
        if directory_node is None:
            return

        # OPCUA NodeIds used when looking for application and cert group
        appdir_node = None
        app_node = None
        certfolder_node = None
        certgroup_node = None

        # Browse Directory node
        for desc in self.browse_node(directory_node):
            if desc.NodeClass == ua.NodeClass.Method:
                if desc.BrowseName.Name in gds_methods:
                    OpcuaGlobalParams.set_gds_method_id(
                        desc.DisplayName.Text,
                        OpcuaNodeId(desc.NodeId.NamespaceIndex, desc.NodeId.Identifier),
                    )
            # Search for applications folder
            elif desc.NodeClass == ua.NodeClass.Object:
                if (
                    desc.TypeDefinition.NamespaceIndex == 0
                    and desc.TypeDefinition.Identifier == 61
                    and desc.BrowseName.Name == "Applications"
                    and appdir_node is None
                ):
                    appdir_node = self.connection.get_node(desc.NodeId)

                # Search for CertificateGroups folder
                elif (
                    desc.TypeDefinition.NamespaceIndex == 0
                    and desc.TypeDefinition.Identifier == 13813
                    and desc.BrowseName.Name == "CertificateGroups"
                    and certfolder_node is None
                ):
                    certfolder_node = self.connection.get_node(desc.NodeId)

        # Retrieve the first app nodeid
        if appdir_node is not None:
            for obj in self.browse_node(appdir_node):
                if obj.NodeClass == ua.NodeClass.Object:
                    # Keep track of our application node
                    app_node = self.connection.get_node(obj.NodeId)

                    # Save application NodeId as bytes
                    OpcuaGlobalParams.set_app_id(to_binary(ua.NodeId, obj.NodeId))
                    break

        # Retrieve our certificate group object, if certificate folder has been found
        if certfolder_node is not None:
            for obj in self.browse_node(certfolder_node, nodeclass=ua.NodeClass.Object):
                # Save application certificate group NodeId as bytes
                OpcuaGlobalParams.set_certgroup_id(to_binary(ua.NodeId, obj.NodeId))
                certgroup_node = self.connection.get_node(obj.NodeId)
                break

        # Retrieve the correct certificate group type
        if certgroup_node is not None:
            for obj in self.browse_node(certgroup_node, name="CertificateTypes"):
                # Save application certificate group type as bytes
                OpcuaGlobalParams.set_certtype_id(to_binary(ua.NodeId, obj.NodeId))
                break

    @property
    def info(self):
        """Return connection URL"""
        return self.url

    def recv(self, max_bytes):
        """Return received bytes with at most `max_bytes`."""
        data = b""
        self.recv_lock.acquire()
        if len(self.recv_buffer) > max_bytes:
            data = self.recv_buffer[:max_bytes]
            self.recv_buffer = self.recv_buffer[max_bytes:]
        elif len(self.recv_buffer) > 0:
            data = self.recv_buffer
            self.recv_buffer = b""
        self.recv_lock.release()

        try:
            resp = struct_from_binary(ua.CallResponse, data)
            print(resp)
        except Exception:
            pass

        # Return data.
        return data

    def recv_all(self, max_bytes: int):
        """Return the received data up to `max_bytes` bytes."""
        return self.recv(max_bytes)

    def set_security(
        self,
        policy,
        client_cert=None,
        key=None,
        password=None,
        sign=False,
        encrypt=False,
    ):
        """Set OPCUA security."""
        if encrypt and sign:
            ua_mode = "SignAndEncrypt"
        elif not encrypt and sign:
            ua_mode = "Sign"
        else:
            ua_mode = "None"

        # Configure security string based on provided parameters.
        self.security = f"{policy},{ua_mode},{client_cert},{key}::{password}"

    def send(self, data: bytes) -> int:
        """Send a binary OPCUA MessageChunk body.

        :return: number of bytes sent
        """
        try:
            # Send our generated UA message (that has no RequestHeader)
            resp = self.loop.run_until_complete(self.connection.uaclient.send_raw(data))

            # Enqueue response
            self.recv_lock.acquire()
            self.recv_buffer += bytes(resp)
            self.recv_lock.release()

            try:
                resp = struct_from_binary(ua.CallResponse, resp)
                print(resp)
            except Exception:
                pass

            return len(data)

        except TimeoutError as tout:
            raise (FuzzowskiTargetConnectionReset(None, None)) from tout
