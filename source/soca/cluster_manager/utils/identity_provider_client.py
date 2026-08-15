# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import re
import logging
from utils.error import SocaError
from utils.config import SocaConfig
from utils.aws.secretsmanager_client import SocaSecret
from utils.response import SocaResponse
from utils.validators import Validators
import ldap
from typing import Optional, Literal, List

logger = logging.getLogger("soca_logger")


def is_initialized(func):
    def wrapper(self, *args, **kwargs):
        if self._conn is None:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper="LDAP connection not initialized, call SocaIdentityProviderClient().initialize() first"
            )
        return func(self, *args, **kwargs)

    return wrapper


class SocaIdentityProviderClient:
    def __init__(
        self,
        provider: Optional[str] = SocaConfig(
            key="/configuration/UserDirectory/provider"
        )
        .get_value()
        .get("message"),
        ldap_endpoint: Optional[str] = None,
        ldap_base_dn: Optional[str] = None,
    ):
        self._provider = provider.lower()
        self._ldap_endpoint = None
        self._ldap_base_dn = None
        self._ldap_domain_name = (
            SocaConfig(key="/configuration/UserDirectory/domain_name")
            .get_value()
            .get("message")
        )
        self._ldap_people_search_base = (
            SocaConfig(key="/configuration/UserDirectory/people_search_base")
            .get_value()
            .get("message")
        )
        self._ldap_group_search_base = (
            SocaConfig(key="/configuration/UserDirectory/group_search_base")
            .get_value()
            .get("message")
        )
        self._ldap_admins_search_dn = (
            SocaConfig(key="/configuration/UserDirectory/admins_search_base")
            .get_value()
            .get("message")
        )
        self._domain_controller_ips = (
            SocaConfig(key="/configuration/UserDirectory/domain_controller_ips")
            .get_value(default=[], return_as=list)
            .get("message")
        )
        self._service_account_secret_arn = (
            SocaConfig(key="/configuration/UserDirectory/service_account_secret_arn")
            .get_value(default=None)
            .get("message")
        )
        self._conn = None
        self._secure_ldap = None

        logger.debug("Initializing SocaIdentityProviderClient")
        if ldap_endpoint is None:
            logger.debug("No ldap endpoint specified, retrieving value on SSM")
            self._ldap_endpoint = (
                SocaConfig(key="/configuration/UserDirectory/endpoint")
                .get_value()
                .get("message")
            )

        if not self._domain_controller_ips:
            logger.warning(
                "/configuration/UserDirectory/domain_controller_ips is empty, SOCA will perform all operations via generic DNS. Specify DC IPs if you want to pin operations on a given AD DC."
            )
        else:
            logger.info(
                f"Domain Controller IPs have been specified {self._domain_controller_ips=}, all operations will default to the first IP in this list "
            )
            self._ldap_endpoint = f"ldap://{self._domain_controller_ips[0]}"

        # Retrieve LDAP Base if not specified
        if ldap_base_dn is None:
            logger.info("No ldap base dn specified, retrieving value on SSM")
            self._ldap_base_dn = (
                SocaConfig(key="/configuration/UserDirectory/domain_base")
                .get_value()
                .get("message")
            )

        self._secure_ldap = (
            True if self._ldap_endpoint.startswith("ldaps://") else False
        )

        logger.debug(
            f"Initialized SocaIdentityProviderClient for {self._provider} with {self.__dict__}"
        )

    @property
    def provider(self) -> Optional[str]:
        return self._provider

    @property
    def ldap_endpoint(self) -> Optional[str]:
        return self._ldap_endpoint

    @property
    def ldap_base_dn(self) -> Optional[str]:
        return self._ldap_base_dn

    @property
    def ldap_domain_name(self) -> Optional[str]:
        return self._ldap_domain_name

    @property
    def ldap_people_search_base(self) -> Optional[str]:
        return self._ldap_people_search_base

    @property
    def ldap_group_search_base(self) -> Optional[str]:
        return self._ldap_group_search_base

    @property
    def ldap_admins_search_dn(self) -> Optional[str]:
        return self._ldap_admins_search_dn

    @property
    def domain_controller_ips(self) -> List[str]:
        return self._domain_controller_ips

    @property
    def service_account_secret_arn(self) -> Optional[str]:
        return self._service_account_secret_arn

    def initialize(
        self,
        trace_level: Optional[Literal[0, 1, 2, 9]] = 0,
        ca_cert_file: Optional[str] = None,
        options: Optional[list] = None,
    ) -> SocaResponse:
        """
        https://www.python-ldap.org/en/python-ldap-3.4.3/reference/ldap.html
        Possible values for trace_level are:
         - 0 for no logging
         - 1 for only logging the method calls with arguments
         - 2 for logging the method calls with arguments and the complete results
         - 9 for also logging the traceback of method calls.

        """
        logger.debug(f"Initializing Identity connection for provider {self._provider}")
        try:
            if not self._ldap_endpoint.startswith(
                "ldaps://"
            ) and not self._ldap_endpoint.startswith("ldap://"):
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper="Invalid ldap endpoint, must start with ldap:// or ldaps://"
                )

            if not re.search(r":\d+$", self._ldap_endpoint):
                logger.debug("No port specified in LDAP endpoint, using default")

            if not options:
                _ldap_initialize_options = []
            else:
                _ldap_initialize_options = options

            if self._secure_ldap:
                logger.debug(
                    f"Secure LDAP detected, disabling TLS_REQCERT as we use self-signed cert by default"
                )
                _ldap_initialize_options.insert(
                    0,
                    (ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER),
                )
                # change to below if you are not using self-signed or have added your CA to system trust store
                # ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)

            if ca_cert_file:
                logger.debug(f"Using CA cert file to establish connection")
                _ldap_initialize_options.insert(
                    0, (ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
                )
                _ldap_initialize_options.insert(
                    0, (ldap.OPT_X_TLS_CACERTFILE, ca_cert_file)
                )
                _ldap_initialize_options.insert(0, (ldap.OPT_X_TLS_NEWCTX, 0))

            # Add all LDAP options
            for option in _ldap_initialize_options:
                # note: Some options are defined automatically by SOCA such as ldap.OPT_X_TLS_REQUIRE_CERT
                # We insert them at the beginning of the array, that way the options will be set BUT can be overridden if manually specified by the user
                if len(option) != 2:
                    return SocaError.IDENTITY_PROVIDER_ERROR(
                        helper=f"Invalid option format, must be a list of tuple (option, value). Detected {option}. List of all options {_ldap_initialize_options}"
                    )
                ldap.set_option(option[0], option[1])

            try:
                self._conn = ldap.initialize(
                    self._ldap_endpoint, trace_level=trace_level
                )
                logger.debug(f"Successfully initialized {self._provider} client")
                return SocaResponse(success=True, message="User is valid")
            except Exception as err:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to initialize ldap due to {err}"
                )

        except Exception as err:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"Error while verifying ldap initialize setup {err}",
            )

    @is_initialized
    def bind_as_service_account(self) -> SocaResponse:
        logger.debug(
            f"Received User Directory Service Account bind request for {self._provider}"
        )
        _secret_id = (
            self._service_account_secret_arn
            if self._service_account_secret_arn is not None
            else "UserDirectoryServiceAccount"
        )
        _secret_prefix = "" if self._service_account_secret_arn else None
        _admin_secret = SocaSecret(
            secret_id=_secret_id, secret_id_prefix=_secret_prefix
        ).get_secret()
        if not _admin_secret.success:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"Unable to retrieve Ldap Admin user/password. Verify IAM role has permission to read secrets: {_admin_secret.get('message')}"
            )

        _admin_user_directory_credentials = _admin_secret.message
        _root_user_dn = _admin_user_directory_credentials.get("username")
        _root_user_password = _admin_user_directory_credentials.get("password")
        logger.info(f"Root User DN: {_root_user_dn}")
        try:
            self._conn.bind_s(_root_user_dn, _root_user_password, ldap.AUTH_SIMPLE)
            logger.debug("UserDirectory: Successfully bind as service account")
            return SocaResponse(
                success=True, message="Successfully bind as service account"
            )

        except ldap.INVALID_CREDENTIALS:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"Unable to bind {_root_user_dn}, verify username and password",
            )
        except Exception as err:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"Unable to bind {_root_user_dn} due to {err}",
            )

    @is_initialized
    def bind_as_user(
        self,
        dn: str,
        password: str,
    ) -> SocaResponse:
        logger.debug(
            f"Received bind request for {dn} with base_dn {self._ldap_people_search_base}"
        )
        # handle case where you just pass a username and not the entire base db
        if self._provider in ["existing_openldap", "openldap"]:
            if self._ldap_people_search_base.lower() not in dn.lower():
                logger.warning(
                    f"SOCA BaseDN for OpenLDAP {self._ldap_people_search_base} not provided on user {dn} ..adding it"
                )
                _user_bind = f"uid={dn},{self._ldap_people_search_base}"
            else:
                _user_bind = dn
        else:
            if self._ldap_domain_name.lower() not in dn.lower():
                logger.warning(
                    f"SOCA Domain name for Active Directory {self._ldap_domain_name} not provided on user {dn} ..adding it"
                )
                _user_bind = f"{dn}@{self._ldap_domain_name}"
            else:
                _user_bind = dn

        logger.info(f"Trying to bind user {_user_bind} with password.")
        try:
            self._conn.bind_s(_user_bind, password, ldap.AUTH_SIMPLE)
            logger.debug("UserDirectory: Successfully bind as user")
            return SocaResponse(success=True, message="User authenticated successfully")

        except ldap.INVALID_CREDENTIALS:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"Invalid credential for {dn}, verify username/password or people OU",
            )
        except Exception as err:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"Unable to bind {dn} due to {err}",
            )

    @is_initialized
    def modify(self, dn: str, mod_list: list) -> SocaResponse:
        # mod_list examples:
        # - [(ldap.MOD_ADD, "memberUid", ["mcrozes".encode()])]
        # - [(ldap.MOD_DELETE, "memberUid", ["mcrozes".encode()]])]
        logger.debug(f"Received modify request {locals()}")
        try:
            self._conn.modify_s(dn, mod_list)
            logger.debug("Resource modified successfully")
            return SocaResponse(
                success=True, message=f"Resource {dn} has been modified successfully"
            )
        except ldap.NO_SUCH_OBJECT:
            return SocaResponse(success=False, message=f"Resource {dn} does not exist.")
        except ldap.UNWILLING_TO_PERFORM as err:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"The LDAP server is unwilling to perform due to {err}"
            )

        except ldap.INSUFFICIENT_ACCESS:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"The service account has insufficient access to perform the operation."
            )

        except Exception as err:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"Unable to modify {dn} with {mod_list} due to {err}",
            )

    @is_initialized
    def add(self, dn: str, mod_list: list) -> SocaResponse:
        # mod_list example:
        # mod_list = [
        #    ("objectClass", ["top".encode("utf-8"), "sudoRole".encode("utf-8")]),
        #    ("sudoHost", ["ALL".encode("utf-8")]),
        #    ("sudoUser", ["mcrozes".encode("utf-8")]),
        #    ("sudoCommand", ["ALL".encode("utf-8")])]
        logger.debug(f"Received add request {locals()}")
        try:
            self._conn.add_s(dn, mod_list)
            logger.debug("Resource has been added successfully")
            return SocaResponse(
                success=True, message=f"Resource {dn} has been added successfully"
            )
        except ldap.INSUFFICIENT_ACCESS:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"The service account has insufficient access to perform the operation"
            )

        except ldap.UNWILLING_TO_PERFORM as err:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"The LDAP server is unwilling to perform due to {err}"
            )

        except Exception as err:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"Unable to add {dn} with {mod_list} due to {err}",
            )

    @is_initialized
    def delete(self, dn: str) -> SocaResponse:
        logger.debug(f"Received delete request {locals()}")
        try:
            self._conn.delete_s(dn)
            logger.debug("Resource deleted successfully")
            return SocaResponse(
                success=True, message=f"Resource {dn} has been deleted successfully"
            )
        except ldap.NO_SUCH_OBJECT:
            return SocaResponse(success=True, message=f"Resource {dn} does not exist.")
        except ldap.INSUFFICIENT_ACCESS:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"The service account has insufficient access to perform the operation"
            )

        except ldap.UNWILLING_TO_PERFORM as err:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"The LDAP server is unwilling to perform due to {err}"
            )

        except Exception as err:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"Unable to delete {dn} due to {err}",
            )

    @is_initialized
    def search(
        self,
        base: str,
        scope: ldap = ldap.SCOPE_SUBTREE,
        filter: str = "(objectClass=*)",
        attr_list: list = None,
        page_size: int = 1000,
        max_results: int = None,
    ) -> SocaResponse:
        logger.debug(f"Received search request {locals()}")
        # Page the search (RFC 2696) so result sets larger than the directory
        # server-side size cap do not raise SIZELIMIT_EXCEEDED. Transparent to
        # callers: the full result set is assembled across pages by looping on
        # the continuation cookie. page_size defaults to 1000 (AWS Managed AD's
        # fixed MaxPageSize); the server returns min(page_size, its own cap) per
        # page, so smaller directories negotiate down gracefully. page_size is a
        # round-trip/memory tuning knob only -- it never affects correctness.
        from ldap.controls import SimplePagedResultsControl

        _page_size = page_size
        try:
            # results are bytes, decoding them
            _decoded_result = []

            # List of bin attr we should not code
            _do_not_decode = ["objectSid"]

            _pg = SimplePagedResultsControl(True, size=_page_size, cookie="")
            while True:
                _msgid = self._conn.search_ext(
                    base, scope, filter, attr_list, serverctrls=[_pg]
                )
                _rtype, _search_result, _rmsgid, _serverctrls = self._conn.result3(
                    _msgid
                )
                for dn, attrs in _search_result:
                    decoded_attrs = {
                        key: [
                            (
                                value.decode("utf-8")
                                if Validators.is_bytes(value) and key not in _do_not_decode
                                else value
                            )
                            for value in values
                        ]
                        for key, values in attrs.items()
                    }
                    _decoded_result.append((dn, decoded_attrs))
                # Early-stop: when the caller only needs a bounded candidate
                # set (e.g. a typeahead that renders [:N]), stop after the page
                # that satisfies max_results instead of walking the full match
                # set. Combined with a small page_size this is a single round
                # trip. Result order is directory order, not ranked.
                if max_results is not None and Validators.is_list_length_greater_equal_than(
                    _decoded_result, max_results
                ):
                    del _decoded_result[max_results:]
                    break
                _cookies = [
                    c.cookie
                    for c in _serverctrls
                    if c.controlType == SimplePagedResultsControl.controlType
                ]
                if _cookies and _cookies[0]:
                    _pg.cookie = _cookies[0]
                else:
                    break
            logger.debug(f"Search Result count: {len(_decoded_result)}")
            return SocaResponse(success=True, message=_decoded_result)

        except ldap.INSUFFICIENT_ACCESS:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"The service account has insufficient access to perform the operation"
            )

        except ldap.UNWILLING_TO_PERFORM as err:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"The LDAP server is unwilling to perform due to {err}"
            )

        except Exception as err:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"Unable to search {base} with scope {scope}, filter {filter}, attr_list {attr_list}, due to {err}",
            )
