"""OPCUA protocol fuzzing

This module contains the definitions of every OPCUA message as well as the
OPCUA session management code.
"""

from typing import Union


def format_uri(uri: Union[str, bytes]) -> bytes:
    """Format URI: remove trailing slash and convert to bytes"""
    # Remove trailing slash if any
    if isinstance(uri, str):
        uri = uri.removesuffix("/")
        return uri.encode("utf-8")
    if isinstance(uri, bytes):
        # Remove last character if '/'
        if uri[-1] == 0x2F:
            uri = uri[:-1]
        return uri
    else:
        # Value must be a str or bytes
        raise ValueError()


class OpcuaGlobalParams:
    """Global OPCUA parameters container class."""

    ENDPOINT_STRING = "".encode("utf-8")
    APP_URI_STRING = "".encode("utf-8")
    GDS_METHODS_IDS = {}
    GDS_DIRECTORY_NODEID = None
    APP_NODEID = None
    CERTGROUP_NODEID = None
    CERTTYPE_NODEID = None

    @staticmethod
    def set_endpoint(endpoint_string: str):
        """Set endpoint URI"""
        OpcuaGlobalParams.ENDPOINT_STRING = format_uri(endpoint_string)

    @staticmethod
    def get_endpoint() -> bytes:
        """Return the current endpoint URI"""
        return OpcuaGlobalParams.ENDPOINT_STRING

    @staticmethod
    def set_app_uri(app_uri_string: str):
        """Set application URI"""
        OpcuaGlobalParams.APP_URI_STRING = format_uri(app_uri_string)

    @staticmethod
    def get_app_uri() -> bytes:
        """Return the current application URI"""
        return OpcuaGlobalParams.APP_URI_STRING

    @staticmethod
    def set_gds_directory_nodeid(nodeid):
        """Save GDS Directory OPCUA NodeId."""
        OpcuaGlobalParams.GDS_DIRECTORY_NODEID = nodeid

    @staticmethod
    def get_gds_directory_nodeid():
        """Retrieve GDS Directory OPCUA NodeId"""
        return OpcuaGlobalParams.GDS_DIRECTORY_NODEID

    @staticmethod
    def set_gds_method_id(name: str, nodeid):
        """Save GDS Directory method's NodeId into our global parameters."""
        OpcuaGlobalParams.GDS_METHODS_IDS[name] = nodeid

    @staticmethod
    def get_gds_method_id(name: str):
        """Retrieve a GDS Directory method's NodeId from its name."""
        if name in OpcuaGlobalParams.GDS_METHODS_IDS:
            return OpcuaGlobalParams.GDS_METHODS_IDS[name]
        return None

    @staticmethod
    def set_app_id(node_id):
        """Save our target OPCUA Application NodeId"""
        OpcuaGlobalParams.APP_NODEID = node_id

    @staticmethod
    def get_app_id():
        """Retrieve our target OPCUA Application NodeId"""
        return OpcuaGlobalParams.APP_NODEID

    @staticmethod
    def set_certgroup_id(node_id):
        """Save our target OPCUA Application CertificateGroup NodeId"""
        OpcuaGlobalParams.CERTGROUP_NODEID = node_id

    @staticmethod
    def get_certgroup_id():
        """Retrieve our target OPCUA Application CertificateGroup NodeId"""
        return OpcuaGlobalParams.CERTGROUP_NODEID

    @staticmethod
    def set_certtype_id(node_id):
        """Save our target OPCUA Application Certificate type NodeId"""
        OpcuaGlobalParams.CERTTYPE_NODEID = node_id

    @staticmethod
    def get_certtype_id():
        """Retrieve our target OPCUA Application Certificate type NodeId"""
        return OpcuaGlobalParams.CERTTYPE_NODEID
