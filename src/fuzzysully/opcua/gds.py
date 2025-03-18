"""Definitions for GDS related requests
"""

import random
import struct

from asyncua.ua.object_ids import ObjectIds
from fuzzowski import (
    s_initialize,
    s_string,
    s_block,
    s_dword,
)
from . import OpcuaGlobalParams
from .helpers import (
    s_type_id,
    s_variant_nodeid,
    s_variant_string,
    s_variant_bytestring,
    s_variant_array_string,
    generate_csr,
)
from ..helpers import s_opcua_array


class OpcuaNodeId:
    """OPCUA NodeId object (OPC 10000-6 section 5.2.2.9)"""

    def __init__(self, namespace: int = 0, node_id: int = 0):
        self.__ns = namespace
        self.__id = node_id

    @property
    def namespace(self) -> int:
        """:return: namespace as an int"""
        return self.__ns

    @property
    def nodeid(self) -> int:
        """:return: node id as an int"""
        return self.__id


def s_opcua_call_request(
    object_node_id: OpcuaNodeId, method_node_id: OpcuaNodeId, args: int
):
    """Create a CallRequest as described in OPC 10000-4 section 5.11.2"""
    # We add the Call binary parameters node
    s_type_id(ObjectIds.CallRequest_Encoding_DefaultBinary)

    # I've added an array to force fuzzysully to generate at least one test case
    with s_opcua_array(name="methods", min_size=1, max_size=1):

        # Directory : ns=2;i=141 (UaGds)
        s_string(
            b"\x01"
            + struct.pack("<B", object_node_id.namespace)
            + struct.pack("<H", object_node_id.nodeid),
            name="object_id",
            fuzzable=False,
        )

        # GetTrustList : ns=2;i=204 (UaGds)
        s_string(
            b"\x01"
            + struct.pack("<B", method_node_id.namespace)
            + struct.pack("<H", method_node_id.nodeid),
            name="method_id",
            fuzzable=False,
        )

        # 2 input parameters
        s_dword(args, name="number_args", fuzzable=False)


def start_signing_request_definition():
    """
    Defines the structure of a Call message.

    OPC 10000-4 - 5.11.2
    """
    s_initialize("StartSigningRequest")

    with s_block("c-body"):

        s_opcua_call_request(
            OpcuaGlobalParams.get_gds_directory_nodeid(),  # Directory NodeId
            OpcuaGlobalParams.get_gds_method_id(
                "StartSigningRequest"
            ),  # StartSigningRequest
            4,
        )

        # Application NodeId (default value taken from discovered application)
        s_variant_nodeid(
            name="app_id", node_id=OpcuaGlobalParams.get_app_id(), fuzzable=True
        )

        # Application certificates group NodeId (default value taken from discovered application cert group)
        s_variant_nodeid(
            name="cert_group_id",
            node_id=OpcuaGlobalParams.get_certgroup_id(),
            fuzzable=True,
        )

        # Application certificates Type NodeId (must be taken from a given parameter)
        s_variant_nodeid(
            name="cert_type_id",
            node_id=OpcuaGlobalParams.get_certtype_id(),
            fuzzable=True,
        )

        csr = generate_csr()

        # Certificate Request Type ByteString
        s_variant_bytestring(name="certif_request", byte_string=csr, fuzzable=True)


def start_new_key_pair_request_definition():
    """
    Defines the structure of a Call message.

    OPC 10000-4 - 5.11.2
    """
    s_initialize("StartNewKeyPairRequest")

    with s_block("c-body"):

        s_opcua_call_request(
            OpcuaGlobalParams.get_gds_directory_nodeid(),  # Directory NodeId
            OpcuaGlobalParams.get_gds_method_id(
                "StartNewKeyPairRequest"
            ),  # StartNewKeyPairRequest
            7,
        )

        # Application NodeId (must be taken from a given parameter)
        s_variant_nodeid(
            name="app_id", node_id=OpcuaGlobalParams.get_app_id(), fuzzable=True
        )

        # Application certificates group NodeId (must be taken from a given parameter)
        s_variant_nodeid(
            name="cert_group_id",
            node_id=OpcuaGlobalParams.get_certgroup_id(),
            fuzzable=True,
        )

        # Application certificates Type NodeId (must be taken from a given parameter)
        s_variant_nodeid(
            name="cert_type_id",
            node_id=OpcuaGlobalParams.get_certtype_id(),
            fuzzable=True,
        )

        # Certificate SubjectName Type String
        s_variant_string(
            name="subject_name",
            string_=b"C=FR/OU=www.random.com/CN=RandomApplication/O=RD",
            fuzzable=True,
        )

        # Certificate DomainNames Type String[]
        s_variant_array_string(
            name="domain_names",
            strings=[b"domain.random", b"random.domain"],
            fuzzable=True,
        )

        # Certificate PrivateKeyFormat Type String
        s_variant_string(name="private_key_format", string_=b"PFX", fuzzable=True)

        # Certificate PrivateKeyPassword Type String
        s_variant_string(
            name="private_key_password", string_=b"passphrase", fuzzable=True
        )


def finish_request_definition():
    """
    Defines the structure of a Call message.

    OPC 10000-4 - 5.11.2
    """
    s_initialize("FinishRequest")

    with s_block("c-body"):

        s_opcua_call_request(
            OpcuaGlobalParams.get_gds_directory_nodeid(),  # Directory NodeId
            OpcuaGlobalParams.get_gds_method_id("FinishRequest"),  # FinishRequest
            2,
        )

        # Application NodeId (must be taken from a given parameter)
        s_variant_nodeid(
            name="app_id", node_id=OpcuaGlobalParams.get_app_id(), fuzzable=True
        )

        # Application request id NodeId
        s_variant_nodeid(
            name="request_id",
            node_id=b"\x01\x03" + struct.pack("<H", 30976),
            fuzzable=True,
        )


def get_trust_list_definition():
    """
    Defines the structure of a Call message.

    OPC 10000-4 - 5.11.2
    """
    s_initialize("GetTrustList")

    with s_block("c-body"):

        s_opcua_call_request(
            OpcuaGlobalParams.get_gds_directory_nodeid(),  # Directory NodeId
            OpcuaGlobalParams.get_gds_method_id("GetTrustList"),  # GetTrustList
            2,
        )

        # Application NodeId (must be taken from a given parameter)
        s_variant_nodeid(
            name="app_id", node_id=OpcuaGlobalParams.get_app_id(), fuzzable=True
        )

        # Application certificates group NodeId (must be taken from a given parameter)
        s_variant_nodeid(
            name="cert_group_id",
            node_id=OpcuaGlobalParams.get_certgroup_id(),
            fuzzable=True,
        )


def get_certificate_groups_definition():
    """
    Defines the structure of a Call message.

    OPC 10000-4 - 5.11.2
    """
    s_initialize("GetCertificateGroups")

    with s_block("c-body"):

        s_opcua_call_request(
            OpcuaGlobalParams.get_gds_directory_nodeid(),  # Directory NodeId
            OpcuaGlobalParams.get_gds_method_id(
                "GetCertificateGroups"
            ),  # GetCertificateGroups
            1,
        )

        # Application NodeId (must be taken from a given parameter)
        s_variant_nodeid(
            name="app_id", node_id=OpcuaGlobalParams.get_app_id(), fuzzable=True
        )


def get_certificate_status_definition():
    """
    Defines the structure of a Call message.

    OPC 10000-4 - 5.11.2
    """
    s_initialize("GetCertificateStatus")

    with s_block("c-body"):

        s_opcua_call_request(
            OpcuaGlobalParams.get_gds_directory_nodeid(),  # Directory NodeId
            OpcuaGlobalParams.get_gds_method_id(
                "GetCertificateStatus"
            ),  # GetCertificateStatus
            3,
        )

        # Application NodeId (must be taken from a given parameter)
        s_variant_nodeid(
            name="app_id", node_id=OpcuaGlobalParams.get_app_id(), fuzzable=True
        )

        # Application certificates group NodeId (must be taken from a given parameter)
        s_variant_nodeid(
            name="cert_group_id",
            node_id=OpcuaGlobalParams.get_certgroup_id(),
            fuzzable=True,
        )

        # Application certificates Type NodeId (must be taken from a given parameter)
        s_variant_nodeid(
            name="cert_type_id",
            node_id=OpcuaGlobalParams.get_certtype_id(),
            fuzzable=True,
        )


def revoke_certificate_definition():
    """
    Defines the structure of a Call message.

    OPC 10000-4 - 5.11.2
    """
    s_initialize("RevokeCertificate")

    with s_block("c-body"):

        s_opcua_call_request(
            OpcuaGlobalParams.get_gds_directory_nodeid(),  # Directory NodeId
            OpcuaGlobalParams.get_gds_method_id("RevokeCertificate"),
            2,
        )

        # Application NodeId (must be taken from a given parameter)
        s_variant_nodeid(
            name="app_id", node_id=OpcuaGlobalParams.get_app_id(), fuzzable=True
        )

        # Random bytes
        certificate = random.randbytes(random.randint(50, 200))

        # Certificate to revoke Type ByteString
        s_variant_bytestring(name="certif", byte_string=certificate, fuzzable=True)
