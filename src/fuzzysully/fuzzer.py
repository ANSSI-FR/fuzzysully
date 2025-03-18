"""This module provide a fuzzer for the OPCUA protocol in three modes:
   - A classical server which exposes services (services are fuzzed).
   - A reverse client to fuzz `reverse_hello`.
   - A GDS server.
"""

from enum import StrEnum

from fuzzowski import s_get, Session
from fuzzowski.fuzzers import IFuzzer
from fuzzowski.mutants.spike import blocks
from fuzzysully.helpers import OPCUASession
from fuzzysully.opcua import OpcuaGlobalParams
from fuzzysully.opcua.attribute import read_definition, history_read_definition
from fuzzysully.opcua.base import (
    hello_definition,
    reverse_hello_definition,
    reverse_hello_error_definition,
)
from fuzzysully.opcua.callbacks.gds import (
    finish_request_start_signing_request_cb,
)
from fuzzysully.opcua.callbacks.hello import (
    reverse_hello_to_error,
)
from fuzzysully.opcua.callbacks.monitor_item import (
    create_monitor_to_publish,
    create_monitor_to_publish_signed,
)
from fuzzysully.opcua.callbacks.secure_channel import (
    open_channel_to_close_channel,
    open_channel_to_any,
    any_to_close_channel,
)
from fuzzysully.opcua.callbacks.session import (
    create_session_to_activate_session,
    activate_to_any,
    any_to_close_session,
    general_body_cb,
)
from fuzzysully.opcua.callbacks.subscription import (
    subscription_to_create_monitor,
    subscription_to_create_monitor_signed,
    delete_monitor_body,
    publish_to_delete_monitor,
    modify_monitor_body,
    publish_to_modify_monitor,
)
from fuzzysully.opcua.gds import (
    start_signing_request_definition,
    start_new_key_pair_request_definition,
    finish_request_definition,
    get_trust_list_definition,
    get_certificate_groups_definition,
    get_certificate_status_definition,
    revoke_certificate_definition,
)
from fuzzysully.opcua.monitor_item import (
    create_monitored_items_definition,
    delete_monitored_items_definition,
    modify_monitored_items_definition,
)
from fuzzysully.opcua.networks import (
    find_servers_definition,
    get_endpoints_definition,
    find_servers_on_network_definition,
    register_server_2_definition,
)
from fuzzysully.opcua.node import add_nodes_definition
from fuzzysully.opcua.secure_channel import (
    open_secure_channel_definition,
    close_secure_channel_definition,
)
from fuzzysully.opcua.session import (
    create_session_definition,
    activate_session_definition,
    close_session_definition,
)
from fuzzysully.opcua.subscription import (
    create_subscription_definition,
    publish_definition,
)
from fuzzysully.opcua.view import (
    browse_definition,
    browse_next_definition,
    register_nodes_definition,
    unregister_nodes_definition,
    translate_browse_path_to_node_ids_definition,
)


class OPCUAMode(StrEnum):
    """Enum which describes the possible types of OPCUA features handled by the fuzzer."""

    GDS = "gds"
    SERVER = "server"
    REVERSE_MODE = "reverse"


class OPCUAFuzzer(IFuzzer):
    """
    This class implement a fuzzer for the OPCUA protocol.
    """

    name = "opcua_fuzzer"

    @classmethod
    def __fuzzable_func_dict(cls, mode: OPCUAMode) -> dict[str, callable]:
        """
        Record the list of implemented tests and the according request names.
        :param mode: an OPCUA mode
        :return: the corresponding dictionary [name : test function]
        """
        # register all the tests implemented in this class
        fuzzable_functions = {
            OPCUAMode.SERVER: {
                "hello": cls.test_hello,
                "secure_channel": cls.test_secure_channel,
                "session": cls.test_session,
                "find_server": cls.test_find_server,
                "get_endpoints": cls.test_get_endpoints,
                "register_server2": cls.test_register_server2,
                "find_server_on_network": cls.test_find_server_on_network,
                "read": cls.test_read,
                "browse": cls.test_browse,
                "browse_next": cls.test_browse_next,
                "history_read": cls.test_history_read,
                "create_subscription": cls.test_create_subscription,
                "add_nodes": cls.test_add_nodes,
                "create_monitor": cls.test_create_monitor,
                "publish": cls.test_publish,
                "delete_monitor": cls.test_delete_monitor,
                "modify_monitor": cls.test_modify_monitor,
                "register_nodes": cls.test_register_nodes,
                "unregister_nodes": cls.test_unregister_nodes,
                "translate_browse_path_to_node_ids": cls.test_translate_browse_path_to_node_ids,
            },
            OPCUAMode.REVERSE_MODE: {
                "reverse_hello": cls.test_reverse_hello,
            },
            OPCUAMode.GDS: {
                "start_signing_request": cls.test_start_signing_request,
                "start_new_key_pair_request": cls.test_start_new_key_pair_request,
                "finish_request": cls.test_finish_request,
                "finish_request_start_signing_request": cls.test_finish_request_start_signing_request,
                "finish_request_start_new_key_pair_request": cls.test_finish_request_start_new_key_pair_request,
                "get_trust_list": cls.test_get_trust_list,
                "get_certificate_groups": cls.test_get_certificate_groups,
                "get_certificate_status": cls.test_get_certificate_status,
                "revoke_certificate": cls.test_revoke_certificate,
            },
        }
        return fuzzable_functions[mode]

    def __init__(self, mode: OPCUAMode, functions_to_fuzz: list = None):
        super().__init__()
        self.OPCUA_mode = mode
        func_dict = self.__fuzzable_func_dict(self.OPCUA_mode)
        if functions_to_fuzz:
            self.specific_funcs = [f for f in functions_to_fuzz if f in func_dict]
        else:
            self.specific_funcs = []

    @classmethod
    def get_requests_name(cls, mode) -> list[str]:
        """
        Get the list of the requests implemented for a given mode.
        :param mode: an OPCUA mode
        :return: a list of request names
        """
        return list(cls.__fuzzable_func_dict(mode).keys())

    def get_requests(self) -> list[(str, callable)]:
        """Get possible requests, returns a list of all the
        callables which connects the paths to the session. (tuple name, callable)
        """
        if len(self.specific_funcs) > 0:
            func_dict = self.__fuzzable_func_dict(self.OPCUA_mode)
            return [(f, func_dict[f]) for f in self.specific_funcs]
        return list(self.__fuzzable_func_dict(self.OPCUA_mode).items())

    @staticmethod
    def define_nodes(mode: OPCUAMode, is_signed: bool, *args, **kwargs) -> None:
        """
        This method define all the possible requests,
        it is called when loading a fuzzer.
        :param mode: OPCUA mode used
        :param is_signed: if the communication uses a Sign or Sign&Encrypt security policy
        """
        if mode == OPCUAMode.SERVER:
            # only None security mode
            hello_definition()
            open_secure_channel_definition()
            close_secure_channel_definition()
            create_session_definition()
            activate_session_definition()
            close_session_definition()
            # None & Sign security mode
            find_servers_definition(is_signed)
            get_endpoints_definition(is_signed)
            register_server_2_definition(is_signed)
            find_servers_on_network_definition(is_signed)
            read_definition(is_signed)
            browse_definition(is_signed)
            browse_next_definition(is_signed)
            history_read_definition(is_signed)
            create_subscription_definition(is_signed)
            add_nodes_definition(is_signed)
            publish_definition(is_signed)
            create_monitored_items_definition(is_signed)
            delete_monitored_items_definition(is_signed)
            modify_monitored_items_definition(is_signed)
            register_nodes_definition(is_signed)
            unregister_nodes_definition(is_signed)
            translate_browse_path_to_node_ids_definition(is_signed)
        elif mode == OPCUAMode.REVERSE_MODE:
            reverse_hello_definition()
            reverse_hello_error_definition()
        else:
            # GDS: declare definitions only for functions exposed by the server
            # (previously discovered)
            if OpcuaGlobalParams.get_gds_method_id("StartSigningRequest") is not None:
                start_signing_request_definition()
            if (
                OpcuaGlobalParams.get_gds_method_id("StartNewKeyPairRequest")
                is not None
            ):
                start_new_key_pair_request_definition()
            if OpcuaGlobalParams.get_gds_method_id("FinishRequest") is not None:
                finish_request_definition()
            if OpcuaGlobalParams.get_gds_method_id("GetTrustList") is not None:
                get_trust_list_definition()
            if OpcuaGlobalParams.get_gds_method_id("GetCertificateGroups") is not None:
                get_certificate_groups_definition()
            if OpcuaGlobalParams.get_gds_method_id("GetCertificateStatus") is not None:
                get_certificate_status_definition()
            if OpcuaGlobalParams.get_gds_method_id("RevokeCertificate") is not None:
                revoke_certificate_definition()

    @staticmethod
    def test_hello(s: Session, is_signed: bool) -> None:
        """Fuzz hello message."""
        if is_signed:
            raise NotImplementedError
        s.connect(s_get("hello"))

    @staticmethod
    def test_secure_channel(s: Session, is_signed: bool) -> None:
        """Fuzz secure channel messages."""
        if is_signed:
            raise NotImplementedError
        s.connect(s_get("hello"))
        s.connect(s_get("hello"), s_get("OpenSecureChannel"))
        s.connect(
            s_get("OpenSecureChannel"),
            s_get("CloseSecureChannel"),
            callback=open_channel_to_close_channel,
        )

    @staticmethod
    def test_session(s: Session, is_signed: bool) -> None:
        """Fuzz CreateSession followed by ActivateSession."""
        if is_signed:
            raise NotImplementedError
        s.connect(s_get("hello"), s_get("OpenSecureChannel"))
        s.connect(
            s_get("OpenSecureChannel"),
            s_get("CreateSession"),
            callback=open_channel_to_any,
        )
        s.connect(
            s_get("CreateSession"),
            s_get("ActivateSession"),
            callback=create_session_to_activate_session,
        )
        s.connect(
            s_get("ActivateSession"),
            s_get("CloseSession"),
            callback=any_to_close_session,
        )
        s.connect(
            s_get("CloseSession"),
            s_get("CloseSecureChannel"),
            callback=any_to_close_channel,
        )

    @staticmethod
    def test_find_server(s: Session, is_signed: bool) -> None:
        """Fuzz FindServers."""
        if is_signed:
            s.connect(s_get("FindServers"), callback=general_body_cb)
            return
        s.connect(s_get("hello"))
        s.connect(s_get("hello"), s_get("OpenSecureChannel"))
        s.connect(
            s_get("OpenSecureChannel"),
            s_get("FindServers"),
            callback=open_channel_to_any,
        )
        s.connect(
            s_get("FindServers"),
            s_get("CloseSecureChannel"),
            callback=any_to_close_channel,
        )

    @staticmethod
    def test_get_endpoints(s: Session, is_signed: bool) -> None:
        """Fuzz GetEndpoints."""
        if is_signed:
            s.connect(s_get("GetEndpoints"))
            return
        s.connect(s_get("hello"))
        s.connect(s_get("hello"), s_get("OpenSecureChannel"))
        s.connect(
            s_get("OpenSecureChannel"),
            s_get("GetEndpoints"),
            callback=open_channel_to_any,
        )
        s.connect(
            s_get("GetEndpoints"),
            s_get("CloseSecureChannel"),
            callback=any_to_close_channel,
        )

    @staticmethod
    def test_register_server2(s: Session, is_signed: bool) -> None:
        """Fuzz RegisterServer2."""
        # It should work, but the test server does not support this service.
        if is_signed:
            s.connect(s_get("RegisterServer2"), callback=general_body_cb)
            return
        s.connect(s_get("hello"))
        s.connect(s_get("hello"), s_get("OpenSecureChannel"))
        s.connect(
            s_get("OpenSecureChannel"),
            s_get("RegisterServer2"),
            callback=open_channel_to_any,
        )
        s.connect(
            s_get("RegisterServer2"),
            s_get("CloseSecureChannel"),
            callback=any_to_close_channel,
        )

    @staticmethod
    def test_find_server_on_network(s: Session, is_signed: bool) -> None:
        """Fuzz find servers on  network message."""
        # It should work, but the test server does not support this service.
        if is_signed:
            s.connect(s_get("FindServersOnNetwork"))
            return
        s.connect(s_get("hello"))
        s.connect(s_get("hello"), s_get("OpenSecureChannel"))
        s.connect(
            s_get("OpenSecureChannel"),
            s_get("FindServersOnNetwork"),
            callback=open_channel_to_any,
        )
        s.connect(
            s_get("FindServersOnNetwork"),
            s_get("CloseSecureChannel"),
            callback=any_to_close_channel,
        )

    @staticmethod
    def test_read(s: OPCUASession, is_signed: bool) -> None:
        """Fuzz Read."""
        if is_signed:
            s.connect(s_get("Read"), callback=general_body_cb)
            return
        s.connect(s_get("hello"))
        s.connect(s_get("hello"), s_get("OpenSecureChannel"))
        s.connect(
            s_get("OpenSecureChannel"),
            s_get("CreateSession"),
            callback=open_channel_to_any,
        )
        s.connect(
            s_get("CreateSession"),
            s_get("ActivateSession"),
            callback=create_session_to_activate_session,
        )
        s.connect(s_get("ActivateSession"), s_get("Read"), callback=activate_to_any)
        s.connect(
            s_get("Read"),
            s_get("CloseSession"),
            callback=any_to_close_session,
        )
        s.connect(
            s_get("CloseSession"),
            s_get("CloseSecureChannel"),
            callback=any_to_close_channel,
        )

    @staticmethod
    def test_browse(s: OPCUASession, is_signed: bool) -> None:
        """Fuzz Browse."""
        if is_signed:
            s.connect(s_get("Browse"), callback=general_body_cb)
            return
        s.connect(s_get("hello"))
        s.connect(s_get("hello"), s_get("OpenSecureChannel"))
        s.connect(
            s_get("OpenSecureChannel"),
            s_get("CreateSession"),
            callback=open_channel_to_any,
        )
        s.connect(
            s_get("CreateSession"),
            s_get("ActivateSession"),
            callback=create_session_to_activate_session,
        )
        s.connect(s_get("ActivateSession"), s_get("Browse"), callback=activate_to_any)
        s.connect(
            s_get("Browse"),
            s_get("CloseSession"),
            callback=any_to_close_session,
        )
        s.connect(
            s_get("CloseSession"),
            s_get("CloseSecureChannel"),
            callback=any_to_close_channel,
        )

    @staticmethod
    def test_browse_next(s: OPCUASession, is_signed: bool) -> None:
        """Fuzz BrowseNext."""
        if is_signed:
            s.connect(s_get("BrowseNext"))
            return
        s.connect(s_get("hello"))
        s.connect(s_get("hello"), s_get("OpenSecureChannel"))
        s.connect(
            s_get("OpenSecureChannel"),
            s_get("CreateSession"),
            callback=open_channel_to_any,
        )
        s.connect(
            s_get("CreateSession"),
            s_get("ActivateSession"),
            callback=create_session_to_activate_session,
        )
        s.connect(
            s_get("ActivateSession"), s_get("BrowseNext"), callback=activate_to_any
        )
        s.connect(
            s_get("BrowseNext"),
            s_get("CloseSession"),
            callback=any_to_close_session,
        )
        s.connect(
            s_get("CloseSession"),
            s_get("CloseSecureChannel"),
            callback=any_to_close_channel,
        )

    @staticmethod
    def test_register_nodes(s: OPCUASession, is_signed: bool) -> None:
        """Fuzz RegisterNodes."""
        if is_signed:
            s.connect(s_get("RegisterNodes"), callback=general_body_cb)
            return
        s.connect(s_get("hello"))
        s.connect(s_get("hello"), s_get("OpenSecureChannel"))
        s.connect(
            s_get("OpenSecureChannel"),
            s_get("CreateSession"),
            callback=open_channel_to_any,
        )
        s.connect(
            s_get("CreateSession"),
            s_get("ActivateSession"),
            callback=create_session_to_activate_session,
        )
        s.connect(
            s_get("ActivateSession"), s_get("RegisterNodes"), callback=activate_to_any
        )
        s.connect(
            s_get("RegisterNodes"),
            s_get("CloseSession"),
            callback=any_to_close_session,
        )
        s.connect(
            s_get("CloseSession"),
            s_get("CloseSecureChannel"),
            callback=any_to_close_channel,
        )

    @staticmethod
    def test_unregister_nodes(s: OPCUASession, is_signed: bool) -> None:
        """Fuzz UnregisterNodes."""
        if is_signed:
            s.connect(s_get("UnregisterNodes"), callback=general_body_cb)
            return
        s.connect(s_get("hello"))
        s.connect(s_get("hello"), s_get("OpenSecureChannel"))
        s.connect(
            s_get("OpenSecureChannel"),
            s_get("CreateSession"),
            callback=open_channel_to_any,
        )
        s.connect(
            s_get("CreateSession"),
            s_get("ActivateSession"),
            callback=create_session_to_activate_session,
        )
        s.connect(
            s_get("ActivateSession"), s_get("UnregisterNodes"), callback=activate_to_any
        )
        s.connect(
            s_get("UnregisterNodes"),
            s_get("CloseSession"),
            callback=any_to_close_session,
        )
        s.connect(
            s_get("CloseSession"),
            s_get("CloseSecureChannel"),
            callback=any_to_close_channel,
        )

    @staticmethod
    def test_history_read(s: OPCUASession, is_signed: bool) -> None:
        # It should work, but the test server does not support this service.
        """Fuzz HistoryRead."""
        if is_signed:
            s.connect(s_get("HistoryRead"), callback=general_body_cb)
            return
        s.connect(s_get("hello"))
        s.connect(s_get("hello"), s_get("OpenSecureChannel"))
        s.connect(
            s_get("OpenSecureChannel"),
            s_get("CreateSession"),
            callback=open_channel_to_any,
        )
        s.connect(
            s_get("CreateSession"),
            s_get("ActivateSession"),
            callback=create_session_to_activate_session,
        )
        s.connect(
            s_get("ActivateSession"), s_get("HistoryRead"), callback=activate_to_any
        )
        s.connect(
            s_get("HistoryRead"),
            s_get("CloseSession"),
            callback=any_to_close_session,
        )
        s.connect(
            s_get("CloseSession"),
            s_get("CloseSecureChannel"),
            callback=any_to_close_channel,
        )

    @staticmethod
    def test_create_subscription(s: OPCUASession, is_signed: bool) -> None:
        """Fuzz CreateSubscription."""
        if is_signed:
            s.connect(s_get("CreateSubscription"), callback=general_body_cb)
            return
        s.connect(s_get("hello"))
        s.connect(s_get("hello"), s_get("OpenSecureChannel"))
        s.connect(
            s_get("OpenSecureChannel"),
            s_get("CreateSession"),
            callback=open_channel_to_any,
        )
        s.connect(
            s_get("CreateSession"),
            s_get("ActivateSession"),
            callback=create_session_to_activate_session,
        )
        s.connect(
            s_get("ActivateSession"),
            s_get("CreateSubscription"),
            callback=activate_to_any,
        )
        s.connect(
            s_get("CreateSubscription"),
            s_get("CloseSession"),
            callback=any_to_close_session,
        )
        s.connect(
            s_get("CloseSession"),
            s_get("CloseSecureChannel"),
            callback=any_to_close_channel,
        )

    @staticmethod
    def test_add_nodes(s: OPCUASession, is_signed: bool) -> None:
        # It should work, but the test server does not support this service.
        """Fuzz AddNodes."""
        if is_signed:
            s.connect(s_get("AddNodes"), callback=general_body_cb)
            return
        s.connect(s_get("hello"))
        s.connect(s_get("hello"), s_get("OpenSecureChannel"))
        s.connect(
            s_get("OpenSecureChannel"),
            s_get("CreateSession"),
            callback=open_channel_to_any,
        )
        s.connect(
            s_get("CreateSession"),
            s_get("ActivateSession"),
            callback=create_session_to_activate_session,
        )
        s.connect(s_get("ActivateSession"), s_get("AddNodes"), callback=activate_to_any)
        s.connect(
            s_get("AddNodes"),
            s_get("CloseSession"),
            callback=any_to_close_session,
        )
        s.connect(
            s_get("CloseSession"),
            s_get("CloseSecureChannel"),
            callback=any_to_close_channel,
        )

    @staticmethod
    def test_publish(s: OPCUASession, is_signed: bool) -> None:
        """Fuzz Publish."""
        if is_signed:
            s.connect(s_get("CreateSubscription"), callback=general_body_cb)
            s.connect(
                s_get("CreateSubscription"),
                s_get("CreateMonitoredItems"),
                callback=subscription_to_create_monitor_signed,
            )
            s.connect(
                s_get("CreateMonitoredItems"),
                s_get("Publish"),
                callback=create_monitor_to_publish_signed,
            )
        else:
            s.connect(s_get("hello"))
            s.connect(s_get("hello"), s_get("OpenSecureChannel"))
            s.connect(
                s_get("OpenSecureChannel"),
                s_get("CreateSession"),
                callback=open_channel_to_any,
            )
            s.connect(
                s_get("CreateSession"),
                s_get("ActivateSession"),
                callback=create_session_to_activate_session,
            )
            s.connect(
                s_get("ActivateSession"),
                s_get("CreateSubscription"),
                callback=activate_to_any,
            )
            s.connect(
                s_get("CreateSubscription"),
                s_get("CreateMonitoredItems"),
                callback=subscription_to_create_monitor,
            )
            s.connect(
                s_get("CreateMonitoredItems"),
                s_get("Publish"),
                callback=create_monitor_to_publish,
            )
            s.connect(
                s_get("Publish"),
                s_get("CloseSession"),
                callback=any_to_close_session,
            )
            s.connect(
                s_get("CloseSession"),
                s_get("CloseSecureChannel"),
                callback=any_to_close_channel,
            )

    @staticmethod
    def test_create_monitor(s: OPCUASession, is_signed: bool) -> None:
        """Fuzz CreateMonitoredItems."""
        if is_signed:
            s.connect(s_get("CreateSubscription"), callback=general_body_cb)
            s.connect(
                s_get("CreateSubscription"),
                s_get("CreateMonitoredItems"),
                callback=subscription_to_create_monitor_signed,
            )
        else:
            s.connect(s_get("hello"))
            s.connect(s_get("hello"), s_get("OpenSecureChannel"))
            s.connect(
                s_get("OpenSecureChannel"),
                s_get("CreateSession"),
                callback=open_channel_to_any,
            )
            s.connect(
                s_get("CreateSession"),
                s_get("ActivateSession"),
                callback=create_session_to_activate_session,
            )
            s.connect(
                s_get("ActivateSession"),
                s_get("CreateSubscription"),
                callback=activate_to_any,
            )
            s.connect(
                s_get("CreateSubscription"),
                s_get("CreateMonitoredItems"),
                callback=subscription_to_create_monitor,
            )
            s.connect(
                s_get("CreateMonitoredItems"),
                s_get("CloseSession"),
                callback=any_to_close_session,
            )
            s.connect(
                s_get("CloseSession"),
                s_get("CloseSecureChannel"),
                callback=any_to_close_channel,
            )

    @staticmethod
    def test_delete_monitor(s: OPCUASession, is_signed: bool) -> None:
        """Fuzz DeleteMonitoredItems."""
        if is_signed:
            s.connect(s_get("CreateSubscription"), callback=general_body_cb)
            s.connect(
                s_get("CreateSubscription"),
                s_get("CreateMonitoredItems"),
                callback=subscription_to_create_monitor_signed,
            )
            s.connect(
                s_get("CreateMonitoredItems"),
                s_get("Publish"),
                callback=create_monitor_to_publish_signed,
            )
            s.connect(
                s_get("Publish"),
                s_get("DeleteMonitoredItems"),
                callback=delete_monitor_body,
            )
        else:
            s.connect(s_get("hello"))
            s.connect(s_get("hello"), s_get("OpenSecureChannel"))
            s.connect(
                s_get("OpenSecureChannel"),
                s_get("CreateSession"),
                callback=open_channel_to_any,
            )
            s.connect(
                s_get("CreateSession"),
                s_get("ActivateSession"),
                callback=create_session_to_activate_session,
            )
            s.connect(
                s_get("ActivateSession"),
                s_get("CreateSubscription"),
                callback=activate_to_any,
            )
            s.connect(
                s_get("CreateSubscription"),
                s_get("CreateMonitoredItems"),
                callback=subscription_to_create_monitor_signed,
            )
            s.connect(
                s_get("CreateMonitoredItems"),
                s_get("Publish"),
                callback=create_monitor_to_publish,
            )
            s.connect(
                s_get("Publish"),
                s_get("DeleteMonitoredItems"),
                callback=publish_to_delete_monitor,
            )
            s.connect(
                s_get("DeleteMonitoredItems"),
                s_get("CloseSession"),
                callback=any_to_close_session,
            )
            s.connect(
                s_get("CloseSession"),
                s_get("CloseSecureChannel"),
                callback=any_to_close_channel,
            )

    @staticmethod
    def test_modify_monitor(s: OPCUASession, is_signed: bool) -> None:
        """Fuzz ModifyMonitoredItems."""
        if is_signed:
            s.connect(s_get("CreateSubscription"), callback=general_body_cb)
            s.connect(
                s_get("CreateSubscription"),
                s_get("CreateMonitoredItems"),
                callback=subscription_to_create_monitor_signed,
            )
            s.connect(
                s_get("CreateMonitoredItems"),
                s_get("Publish"),
                callback=create_monitor_to_publish_signed,
            )
            s.connect(
                s_get("Publish"),
                s_get("ModifyMonitoredItems"),
                callback=modify_monitor_body,
            )
            s.connect(
                s_get("ModifyMonitoredItems"),
                s_get("DeleteMonitoredItems"),
                callback=delete_monitor_body,
            )
        else:
            s.connect(s_get("hello"))
            s.connect(s_get("hello"), s_get("OpenSecureChannel"))
            s.connect(
                s_get("OpenSecureChannel"),
                s_get("CreateSession"),
                callback=open_channel_to_any,
            )
            s.connect(
                s_get("CreateSession"),
                s_get("ActivateSession"),
                callback=create_session_to_activate_session,
            )
            s.connect(
                s_get("ActivateSession"),
                s_get("CreateSubscription"),
                callback=activate_to_any,
            )
            s.connect(
                s_get("CreateSubscription"),
                s_get("CreateMonitoredItems"),
                callback=subscription_to_create_monitor_signed,
            )
            s.connect(
                s_get("CreateMonitoredItems"),
                s_get("Publish"),
                callback=create_monitor_to_publish,
            )
            s.connect(
                s_get("Publish"),
                s_get("ModifyMonitoredItems"),
                callback=publish_to_modify_monitor,
            )
            s.connect(
                s_get("ModifyMonitoredItems"),
                s_get("DeleteMonitoredItems"),
                callback=delete_monitor_body,
            )
            s.connect(
                s_get("DeleteMonitoredItems"),
                s_get("CloseSession"),
                callback=any_to_close_session,
            )
            s.connect(
                s_get("CloseSession"),
                s_get("CloseSecureChannel"),
                callback=any_to_close_channel,
            )

    @staticmethod
    def test_translate_browse_path_to_node_ids(
        s: OPCUASession, is_signed: bool
    ) -> None:
        """Fuzz TranslateBrowsePathsToNodeIds."""
        if is_signed:
            s.connect(s_get("TranslateBrowsePathsToNodeIds"), callback=general_body_cb)
            return
        s.connect(s_get("hello"))
        s.connect(s_get("hello"), s_get("OpenSecureChannel"))
        s.connect(
            s_get("OpenSecureChannel"),
            s_get("CreateSession"),
            callback=open_channel_to_any,
        )
        s.connect(
            s_get("CreateSession"),
            s_get("ActivateSession"),
            callback=create_session_to_activate_session,
        )
        s.connect(
            s_get("ActivateSession"),
            s_get("TranslateBrowsePathsToNodeIds"),
            callback=activate_to_any,
        )
        s.connect(
            s_get("TranslateBrowsePathsToNodeIds"),
            s_get("CloseSession"),
            callback=any_to_close_session,
        )
        s.connect(
            s_get("CloseSession"),
            s_get("CloseSecureChannel"),
            callback=any_to_close_channel,
        )

    # -------------------------- REVERSE MODE --------------------------------
    @staticmethod
    def test_reverse_hello(s: Session, *args, **kwargs) -> None:
        """Fuzz reverse hello message."""
        s.connect(s_get("ReverseHello"))
        s.connect(
            s_get("ReverseHello"),
            s_get("ReverseHelloError"),
            callback=reverse_hello_to_error,
        )

    # ---------------------------- GDS MODE ----------------------------------
    @staticmethod
    def test_start_signing_request(s: Session) -> None:
        """Fuzz certificate manager StartSigningRequest."""

        # Make sure our StartSigningRequest node is already declared
        if "StartSigningRequest" in blocks.REQUESTS:
            s.connect(s_get("StartSigningRequest"))

    @staticmethod
    def test_start_new_key_pair_request(s: Session) -> None:
        """Fuzz certificate manager StartNewKeyPairRequest."""

        # Make sure our StartNewKeyPairRequest node is already declared
        if "StartNewKeyPairRequest" in blocks.REQUESTS:
            s.connect(s_get("StartNewKeyPairRequest"))

    @staticmethod
    def test_finish_request(s: Session) -> None:
        """Fuzz certificate manager FinishRequest."""

        # Make sure our nodes have been declared
        if "FinishRequest" in blocks.REQUESTS:
            s.connect(s_get("FinishRequest"))

    @staticmethod
    def test_finish_request_start_signing_request(s: OPCUASession) -> None:
        """Fuzz certificate manager FinishRequest preceded by StartSigningRequest."""

        # Make sure our nodes have been declared
        if (
            "StartSigningRequest" in blocks.REQUESTS
            and "FinishRequest" in blocks.REQUESTS
        ):
            s.connect(s_get("StartSigningRequest"))
            s.connect(
                s_get("StartSigningRequest"),
                s_get("FinishRequest"),
                callback=finish_request_start_signing_request_cb,
            )

    @staticmethod
    def test_finish_request_start_new_key_pair_request(s: Session) -> None:
        """Fuzz certificate manager FinishRequest preceded by StartNewKeyPairRequest."""

        # Make sure our nodes have been declared
        if (
            "StartNewKeyPairRequest" in blocks.REQUESTS
            and "FinishRequest" in blocks.REQUESTS
        ):
            s.connect(s_get("StartNewKeyPairRequest"))
            s.connect(
                s_get("StartNewKeyPairRequest"),
                s_get("FinishRequest"),
                callback=finish_request_start_signing_request_cb,
            )

    @staticmethod
    def test_get_trust_list(s: Session) -> None:
        """Fuzz certificate manager GetTrustList."""

        # Make sure our GetCertificateGroups node has been declared
        if "GetTrustList" in blocks.REQUESTS:
            s.connect(s_get("GetTrustList"))

    @staticmethod
    def test_get_certificate_groups(s: Session) -> None:
        """Fuzz certificate manager GetCertificateGroups."""

        # Make sure our GetCertificateGroups node has been declared
        if "GetCertificateGroups" in blocks.REQUESTS:
            s.connect(s_get("GetCertificateGroups"))

    @staticmethod
    def test_get_certificate_status(s: Session) -> None:
        """Fuzz certificate manager GetCertificateStatus."""

        # Make sure our GetCertificateStatus node has been declared
        if "GetCertificateStatus" in blocks.REQUESTS:
            s.connect(s_get("GetCertificateStatus"))

    @staticmethod
    def test_revoke_certificate(s: Session) -> None:
        """Fuzz certificate manager RevokeCertificate."""

        # Make sure our GetCertificateStatus node has been declared
        if "RevokeCertificate" in blocks.REQUESTS:
            s.connect(s_get("RevokeCertificate"))
