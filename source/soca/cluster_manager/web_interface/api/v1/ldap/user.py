######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

import hashlib
import os
import re
import stat
import pwd
import json
import subprocess
from base64 import b64encode as encode
from email.utils import parseaddr
import config
from flask_restful import Resource, reqparse
import logging
from flask import request
from flask_babel import gettext as _
from decorators import private_api, admin_api, feature_flag
import sys
import shutil
from datetime import datetime, timezone
from utils.identity_provider_client import SocaIdentityProviderClient
import struct
from utils.subprocess_client import SocaSubprocessClient
from utils.http_client import SocaHttpClient
from utils.error import SocaError
from utils.response import SocaResponse
import grp
import ldap

logger = logging.getLogger("soca_logger")
import time


def populate_ssh_keys(username: str, user_path: str) -> bool:
    """
    Generate SSH keypairs and store them in the user's home directory
    """
    logger.info(f"Generating SSH keypairs for {username=} / {user_path=}")

    if not username:
        logger.error("populate_ssh_keys Missing username")
        return False

    if not user_path:
        logger.error("populate_ssh_keys Missing user_path")
        return False

    # Create the .ssh directory for the user
    _ssh_path_str: str = f"{user_path}/.ssh"

    # The SSH keys to generate from ssh-keygen
    # This is done as a dict so you can modify the per-key args if desired
    _ssh_key_dict: dict = {
        # Adjust the generated key types for your specific environment based on the security threats and policy
        "rsa": {
            "command": f"su {username} -c 'ssh-keygen -t rsa -b 4096 -f {_ssh_path_str}/id_rsa -N \""
            "\" '",
        },
        "ed25519": {
            "command": f"su {username} -c 'ssh-keygen -t ed25519 -f {_ssh_path_str}/id_ed25519 -N \""
            "\" '",
        },
        # "dsa":  {
        #     "command": f"su {username} -c 'ssh-keygen -t dsa -f {_ssh_path_str}/id_dsa -N \"""\" '",
        # },
        # "ecdsa": {
        #     "command": f"su {username} -c 'ssh-keygen -t ecdsa -f {_ssh_path_str}/id_ecdsa -N \"""\" '",
        # },
    }

    logger.debug(f"{_ssh_key_dict}")

    _ssh_keys_generated: int = 0
    for _ssh_key_type, _ssh_keygen_data in _ssh_key_dict.items():
        logger.info(f"Trying to create SSH key of type {_ssh_key_type}")
        _cmd = _ssh_keygen_data.get("command", "")

        if not _cmd:
            logger.error(f"Missing command for SSH keytype - {_ssh_key_type}")
            continue

        logger.info(f"Generating ssh_key {_ssh_key_type=} via {_cmd=}")
        try:
            _ssh_key_result = SocaSubprocessClient(run_command=_cmd).run()
            if _ssh_key_result.get("message") is False:
                logger.error(
                    f"Unable to generate {_ssh_key_type} - {_ssh_key_result=} because of  {_ssh_key_result.get('message')}"
                )
                continue
            else:
                logger.debug(
                    f"ssh_key_result for type {_ssh_key_type} - {_ssh_key_result=}"
                )
                _ssh_keys_generated += 1

        except Exception as e:
            logger.error(
                f"Unable to generate SSH keypair for keytype {_ssh_key_type} - {e}"
            )
            continue
        finally:
            logger.debug(f"ssh_key_result for type {_ssh_key_type}")

    # Did we generate all the desired keypair types?
    if _ssh_keys_generated == len(_ssh_key_dict):
        logger.info(f"Done generating all ({_ssh_keys_generated}) keypairs for user")
    else:
        logger.warning(
            f"Unable to generate all SSH keypairs - Generated {_ssh_keys_generated} of {len(_ssh_key_dict)} keypairs. Check log for errors"
        )

    return True


def _chown_with_lookup_retry(path: str, user: str, group=None,
                             max_attempts: int = 3, delay: float = 2.0,
                             telemetry=None) -> bool:
    """
    shutil.chown wrapper that retries on LookupError (raised when sssd
    hasn't yet caught up to the AD add and pwd.getpwnam fails).

    Bounded by `max_attempts * delay` — default 6s — so a slow sssd
    refresh recovers without permanently blocking the request.
    Returns True on success, False if all attempts exhausted.

    `telemetry`: optional _CreateUserTelemetry for retry-count tracking.
    """
    import time as _time
    for _attempt in range(max_attempts):
        try:
            if group is None:
                shutil.chown(path=path, user=user)
            else:
                shutil.chown(path=path, user=user, group=group)
            return True
        except LookupError as _err:
            if telemetry is not None:
                telemetry.incr("chown_retries")
            if _attempt == max_attempts - 1:
                logger.error(
                    "chown %s -> %s:%s still failing after %d attempts: %s",
                    path, user, group, max_attempts, _err,
                )
                return False
            logger.warning(
                "chown %s -> %s:%s LookupError attempt %d/%d (sssd lag): %s; "
                "retrying in %.1fs",
                path, user, group, _attempt + 1, max_attempts, _err, delay,
            )
            _time.sleep(delay)
    return False


# ---------------------------------------------------------------------------
# Per-request telemetry — counts loops/retries + emits structured log line
# and best-effort CloudWatch metrics. Critical for scale validation: lets
# us see "did sssd take 1 poll or 14?" across many users.
# ---------------------------------------------------------------------------
class _CreateUserTelemetry:
    """Accumulates per-create telemetry for one POST /api/ldap/user call.

    Counters tracked:
      sssd_polls       — # iterations of the visibility loop until success (1..15)
      chown_retries    — # LookupError retries during create_home chown calls
      sss_cache_rc     — return code of `sss_cache -E` (0 = OK, None = skipped/error)
      home_dir_status  — "ok" | "fail" | "skipped"

    Timings (milliseconds since start of post()):
      ad_add_ms, sss_cache_ms, sssd_visible_ms, home_dir_ms, group_add_ms,
      api_key_ms, total_ms
    """

    def __init__(self, username: str):
        self.username = username
        self._t0 = time.monotonic()
        self.counters: dict = {
            "sssd_polls":      0,
            "chown_retries":   0,
            "sss_cache_rc":    None,
            "home_dir_status": "skipped",
        }
        self.timings: dict = {}     # name -> elapsed_ms
        self.outcome: str = "ok"    # ok | soft | fail

    def mark(self, name: str) -> None:
        """Record elapsed-since-start in milliseconds for a named milestone."""
        self.timings[name] = int((time.monotonic() - self._t0) * 1000)

    def incr(self, name: str, by: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + by

    def set(self, name: str, value) -> None:
        self.counters[name] = value

    def emit(self, cluster_id: str = "", outcome: str = None) -> None:
        """Final emission — INFO-level structured log line. Safe to call
        exactly once at end of request. Single-line JSON so CloudWatch
        Logs Insights / `awk` / `jq` can parse it without ceremony."""
        if outcome is not None:
            self.outcome = outcome
        self.mark("total_ms")  # final
        payload = {
            "event": "user_create_telemetry",
            "user": self.username,
            "cluster": cluster_id,
            "outcome": self.outcome,
            "counters": dict(self.counters),
            "timings_ms": dict(self.timings),
        }
        try:
            logger.info(f"[user-create-telemetry] {json.dumps(payload, default=str)}")
        except Exception:
            logger.info(f"[user-create-telemetry] {payload}")


def create_home(username: str, group: str, telemetry=None):
    try:
        user_home = config.Config.USER_HOME
        logger.info(
            f"Creating new HOME for {username=}, {group=}, {user_home=}/{username}"
        )

        # Create user directory structure
        user_path = f"{user_home}/{username}"

        for _create_dir in [user_path, f"{user_path}/.ssh"]:
            logger.info(f"Creating {_create_dir}")

            if ".ssh" in _create_dir:
                # Keep the SSH directory protected - only accessible by the user
                _permissions = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
            else:
                # Home dir by default allows the user group to have access
                _permissions = (
                    stat.S_IRUSR
                    | stat.S_IWUSR
                    | stat.S_IXUSR
                    | stat.S_IRGRP
                    | stat.S_IXGRP
                )

            # Symlink-safe create: refuse a pre-planted symlink at the home path (loose-perm shared mounts).
            try:
                os.mkdir(_create_dir, mode=_permissions)
            except FileExistsError:
                if stat.S_ISLNK(os.lstat(_create_dir).st_mode):
                    logger.error(f"Refusing to provision: {_create_dir} is a symlink")
                    return False
            _dfd = os.open(_create_dir, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
            try:
                os.fchmod(_dfd, _permissions)
            finally:
                os.close(_dfd)

        # Copy default .bash profile
        _default_skel = [
            "/etc/skel/.bashrc",
            "/etc/skel/.bash_profile",
            "/etc/skel/.bash_logout",
        ]
        for _skel in _default_skel:
            if os.path.exists(_skel):
                shutil.copy(src=_skel, dst=user_path)
            else:
                logger.warning(
                    f"Unable to copy {_skel}, file does not exist, ignoring ... "
                )

        # Adjust file/folder ownership
        try:
            group = grp.getgrnam(group).gr_name
        except KeyError:
            logger.warning(
                f"Unable to determine gr_name for {group}, trying to get primary group id for {username}"
            )
            try:
                group = pwd.getpwnam(username).pw_gid
            except Exception as err:
                logger.warning(
                    f"Unable to get default group id for {username} due to {err}"
                )
                # Handle case where group does not exist (e.g when using an external directory) or if SOCA can't determine it
                group = None

        for _path in [
            f"{user_path}",
            f"{user_path}/.ssh",
            f"{user_path}/.bashrc",
            f"{user_path}/.bash_profile",
            f"{user_path}/.bash_logout",
        ]:
            logger.info(
                f"About to chown {_path=} hierarchy with {username=} and {group=}"
            )
            if os.path.exists(_path):
                if group is None:
                    logger.warning(
                        f"Unable to detect group name for {username} ,group membership won't be set. Change it afterwards if needed."
                    )
                    if not _chown_with_lookup_retry(_path, username, telemetry=telemetry):
                        return False
                else:
                    if not _chown_with_lookup_retry(_path, username, group, telemetry=telemetry):
                        return False
            else:
                logger.warning(f"Unable to chown {_path}, path does not exist")

        logger.info(f"Create SSH keypairs for {username}")
        if not populate_ssh_keys(username=username, user_path=user_path):
            logger.error(f"Unable to generate SSH keypairs for user {username}")
            return False

        logger.info("Configuring authorized_keys based on ssh keypairs created")
        _authorized_keys_file = f"{user_path}/.ssh/authorized_keys"
        os.makedirs(os.path.dirname(_authorized_keys_file), exist_ok=True)
        # O_NOFOLLOW: never append through a symlink planted at authorized_keys.
        _ak_fd = os.open(_authorized_keys_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(_ak_fd, "a") as authorized_keys_file:
            for filename in os.listdir(f"{user_path}/.ssh"):
                if filename.endswith(".pub"):
                    pub_key_path = os.path.join(f"{user_path}/.ssh", filename)
                    with open(pub_key_path, "r") as pub_key_file:
                        pub_key_content = pub_key_file.read()
                        authorized_keys_file.write(pub_key_content + "\n")

        logger.info(
            "Enforcing right permissions for all files within .ssh folder post keypair creation"
        )
        for root, dirs, files in os.walk(f"{user_path}/.ssh"):
            for _file in files:
                _file_path = os.path.join(root, _file)
                logger.info(f"Changing permissions for {_file_path}")
                os.chmod(_file_path, stat.S_IRUSR | stat.S_IWUSR)
                # By the time we get here, the first chown loop has
                # already resolved sssd → user. A LookupError here
                # would be unexpected, but the helper still costs nothing
                # for the success case.
                if not _chown_with_lookup_retry(_file_path, username, group, telemetry=telemetry):
                    return False

        return True

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logger.error(
            f"Error while trying to create home directory for  {username}, {exc_type} {fname}, {exc_tb.tb_lineno}"
        )
        return False


class User(Resource):
    @private_api
    def get(self):
        """
        Get user information
        ---
        openapi: 3.1.0
        operationId: getLdapUser
        tags:
          - User Management
        summary: Get user information
        description: Retrieve detailed information for a specific LDAP user by username or DN
        security:
          - socaAuth: []
        parameters:
          - name: user
            in: query
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 256
              example: "john.doe"
            description: Username or DN of the user to retrieve
        responses:
          '200':
            description: Successfully retrieved user information
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: array
                      items:
                        type: array
                        description: LDAP entry data
                      example: [["cn=john.doe,ou=people,dc=soca,dc=local", {"uid": ["john.doe"]}]]
          '203':
            description: User not found
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "User not found"
          '400':
            description: Missing required parameter
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Missing required parameter: user"
          '500':
            description: Internal server error
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to connect to LDAP server"
        components:
          securitySchemes:
            socaAuth:
              type: apiKey
              in: header
              name: X-EDH-USER
              description: SOCA username for authentication
            socaToken:
              type: apiKey
              in: header
              name: X-EDH-TOKEN
              description: SOCA authentication token
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="args")
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        try:

            if config.Config.DIRECTORY_AUTH_PROVIDER in [
                "openldap",
                "existing_openldap",
            ]:
                _filter = f"(&(objectClass=person)(uid={user}))"
                _attrs = ["uid"]
            else:
                if config.Config.DIRECTORY_PEOPLE_SEARCH_BASE.lower() in user.lower():
                    _filter = f"(&(objectClass=user)(distinguishedName={user}))"
                else:
                    _filter = f"(&(objectClass=user)(sAMAccountName={user}))"
                # Attrs is important otherwise response will contains non-utf8 char (sID etc)
                _attrs = ["sAMAccountName"]

            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            _search_user = _soca_identity_client.search(
                base=config.Config.DIRECTORY_PEOPLE_SEARCH_BASE,
                filter=_filter,
                attr_list=_attrs,
            )

            if _search_user.success:
                return SocaResponse(
                    success=True, message=_search_user.message
                ).as_flask()
            else:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to find user because of {_search_user.message}"
                ).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

    @admin_api
    @feature_flag(flag_name="USERS_GROUPS_MANAGEMENT", mode="api")
    def post(self):
        """
        Create new user
        ---
        openapi: 3.1.0
        operationId: createLdapUser
        tags:
          - User Management
        summary: Create new user
        description: Create a new LDAP user with home directory, SSH keys, and group membership
        security:
          - socaAuth: []
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - user
                  - password
                  - sudoers
                  - email
                properties:
                  user:
                    type: string
                    description: Username for the new user (alphanumeric, _, -, . allowed, max 31 chars)
                    minLength: 1
                    maxLength: 31
                    pattern: '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'
                    example: "john.doe"
                  password:
                    type: string
                    description: Password for the new user
                    minLength: 1
                    format: password
                    example: "SecurePass123!"
                  sudoers:
                    type: integer
                    description: Grant sudo permissions (1 = yes, 0 = no)
                    enum: [0, 1]
                    example: 0
                  email:
                    type: string
                    description: Email address for the user
                    format: email
                    example: "john.doe@company.com"
                  shell:
                    type: string
                    description: Login shell for the user
                    default: "/bin/bash"
                    example: "/bin/bash"
                  uid:
                    type: integer
                    description: Linux UID (0 = auto-assign)
                    minimum: 0
                    maximum: 65535
                    default: 0
                    example: 1001
                  gid:
                    type: integer
                    description: Linux GID (0 = auto-assign)
                    minimum: 0
                    maximum: 65535
                    default: 0
                    example: 1001
        responses:
          '200':
            description: User created successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: string
                      example: "User created"
          '203':
            description: User already exists
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to create user, john.doe already exist"
          '400':
            description: Invalid input parameters
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Missing required parameter: user"
          '500':
            description: Internal server error
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to create user due to LDAP error"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="form")
        parser.add_argument("password", type=str, location="form")
        parser.add_argument("sudoers", type=int, location="form")
        parser.add_argument("email", type=str, location="form")
        parser.add_argument("shell", type=str, location="form")
        parser.add_argument(
            "uid", type=int, location="form"
        )  # 0 = no value specified, use default one
        parser.add_argument(
            "gid", type=int, location="form"
        )  # 0 = no value specified, use default one
        args = parser.parse_args()

        if args.get("user", None) is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        if re.match(config.Config.USER_REGEX_PATTERN, args["user"]):
            user = args["user"].lower()
        else:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"User {args['user']} is not valid, must match {config.Config.USER_REGEX_PATTERN} (contains -and start with- only alpha-numerical characters plus _ . - and must be 31 chars max"
            ).as_flask()

        # Telemetry: tracks loops/retries/timings for scale validation.
        # Cluster id is read here once so the telemetry's CW emission
        # carries the right dimension. Best-effort lookup; if SocaConfig
        # is unavailable we still log the structured line.
        _telemetry = _CreateUserTelemetry(username=user)
        try:
            from utils.config import SocaConfig as _SocaConfig
            _cluster_id = _SocaConfig(key="/configuration/ClusterId").get_value().get("message", "") or ""
        except Exception:
            _cluster_id = ""

        password = args["password"]
        sudoers = args["sudoers"]
        email = args["email"]
        uid = args["uid"]
        gid = args["gid"]
        shell = args["shell"]
        group = f"{args['user']}{config.Config.DIRECTORY_GROUP_NAME_SUFFIX}"

        people_search_base = config.Config.DIRECTORY_PEOPLE_SEARCH_BASE

        if shell is None:
            logger.warning(
                "shell not specified for new user creation, default to /bin/bash"
            )
            shell = "/bin/bash"

        if password is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="password").as_flask()

        if config.Config.DIRECTORY_AUTH_PROVIDER in ["aws_ds_managed_activedirectory"]:
            ds_password_complexity = r"(?=^.{8,64}$)((?=.*\d)(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[^A-Za-z0-9\s])(?=.*[a-z])|(?=.*[^A-Za-z0-9\s])(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[A-Z])(?=.*[^A-Za-z0-9\s]))^.*"
            if not re.search(ds_password_complexity, password):
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"The password must be 8 to 64 characters long and include at least three of the following four types: uppercase letters, lowercase letters, numbers, and special characters."
                ).as_flask()
            if user.lower() in password.lower():
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"The password cannot contain the username."
                ).as_flask()

        if sudoers is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="sudoers").as_flask()

        if email is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="email").as_flask()

        _get_id = SocaHttpClient(
            endpoint="/api/ldap/ids",
            headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
        ).get()
        if _get_id.success:
            current_ldap_ids = _get_id.message
        else:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"/api/ldap/ids returned error: {_get_id.message}"
            ).as_flask()

        # `uid` / `gid` of 0 OR omitted-from-form (None) both mean
        # "auto-assign". Without the None check, an absent uid falls
        # through to the duplicate-check branch, then ships the literal
        # Python None to LDAP as the string "None" → AD rejects with
        # "Invalid syntax" (DSID-0C0913EC, attribute conversion error).
        if uid is None or uid == 0:
            uid = current_ldap_ids["proposed_uid"]
        else:
            if uid in current_ldap_ids["uid_in_use"]:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to create user {user}, UID {uid} already in use"
                ).as_flask()

        if gid is None or gid == 0:
            gid = current_ldap_ids["proposed_gid"]
        else:
            if gid in current_ldap_ids["gid_in_use"]:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to create user {user}, GID {gid} already in use"
                ).as_flask()

        # Note: parseaddr adheres to rfc5322 , which means user@domain is a correct address.
        # You do not necessarily need to add a tld at the end
        if "@" not in parseaddr(email)[1]:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"Unable to create user {user}, Invalid email address"
            ).as_flask()

        _non_blocking_errors = []
        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()

            _is_user_exist = SocaHttpClient(
                endpoint="/api/ldap/user",
                headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
            ).get(params={"user": user})
            if _is_user_exist.get('success'):
                if len(_is_user_exist.get('message')) == 0:
                    pass
                else:
                    return SocaError.IDENTITY_PROVIDER_ERROR(
                        helper=f"Unable to create user, {user} already exist"
                    ).as_flask()
            else:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to check if user {user} already exist, {_is_user_exist.message}"
                ).as_flask()

            if config.Config.DIRECTORY_AUTH_PROVIDER in [
                "openldap",
                "existing_openldap",
            ]:
                _dn_user = f"uid={user},{people_search_base}"
                enc_passwd = bytes(password, "utf-8")
                salt = os.urandom(16)
                sha = hashlib.sha1(enc_passwd)  # nosec
                sha.update(salt)
                digest = sha.digest()
                b64_envelop = encode(digest + salt)
                passwd = "{{SSHA}}{}".format(b64_envelop.decode("utf-8"))
                _attrs = [
                    (
                        "objectClass",
                        [
                            "top".encode("utf-8"),
                            "person".encode("utf-8"),
                            "posixAccount".encode("utf-8"),
                            "shadowAccount".encode("utf-8"),
                            "inetOrgPerson".encode("utf-8"),
                            "organizationalPerson".encode("utf-8"),
                        ],
                    ),
                    ("uid", [str(user).encode("utf-8")]),
                    ("uidNumber", [str(uid).encode("utf-8")]),
                    ("gidNumber", [str(gid).encode("utf-8")]),
                    ("mail", [str(email).encode("utf-8")]),
                    ("cn", [str(user).encode("utf-8")]),
                    ("sn", [str(user).encode("utf-8")]),
                    ("loginShell", [str(shell).encode("utf-8")]),
                    (
                        "homeDirectory",
                        (config.Config.USER_HOME + "/" + str(user)).encode("utf-8"),
                    ),
                    ("userPassword", [passwd.encode("utf-8")]),
                ]

            else:
                # note: for MAD/SAD, password management is done via LambDa
                _dn_user = f"cn={user},{config.Config.DIRECTORY_PEOPLE_SEARCH_BASE}"
                _attrs = [
                    (
                        "objectClass",
                        [
                            "top".encode("utf-8"),
                            "person".encode("utf-8"),
                            "user".encode("utf-8"),
                            "organizationalPerson".encode("utf-8"),
                        ],
                    ),
                    ("displayName", [str(user).encode("utf-8")]),
                    ("mail", [str(email).encode("utf-8")]),
                    ("sAMAccountName", [str(user).encode("utf-8")]),
                    (
                        "userPrincipalName",
                        [
                            str(
                                user + "@" + config.Config.DIRECTORY_DOMAIN_NAME
                            ).encode("utf-8")
                        ],
                    ),
                    ("cn", [str(user).encode("utf-8")]),
                    ("uidNumber", [str(uid).encode("utf-8")]),
                    ("uid", [str(uid).encode("utf-8")]),
                    ("gidNumber", [str(gid).encode("utf-8")]),
                    ("loginShell", [shell.encode("utf-8")]),
                    (
                        "homeDirectory",
                        (str(config.Config.USER_HOME) + "/" + str(user)).encode(
                            "utf-8"
                        ),
                    ),
                ]

            logger.info(f"About to create new account {user}")

            logger.info("Create group first to prevent GID issue")
            _create_user_group = SocaHttpClient(
                endpoint="/api/ldap/group",
                headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
            ).post(data={"group": f"{group}", "gid": gid})
            if _create_user_group.get("success") is False:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to create group {group} because of {_create_user_group.get('message')}"
                ).as_flask()
            logger.info(f"Group {group} created successfully")

            logger.info(f"About to create actual user")
            _user_create = _soca_identity_client.add(dn=_dn_user, mod_list=_attrs)
            if _user_create.get("success") is False:
                logger.info(
                    f"Unable to create user {_dn_user}, deleting associated group {group}"
                )
                SocaHttpClient(
                    endpoint="/api/ldap/group",
                    headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
                ).delete(data={"group": f"{group}"})
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to create user {user}, because of {_user_create.get('message')}"
                ).as_flask()
            else:
                logger.info(f"User {user} created successfully")
                _telemetry.mark("ad_add_ms")

            if config.Config.DIRECTORY_AUTH_PROVIDER in [
                "aws_ds_managed_activedirectory",
            ]:
                logger.info(
                    "Set up Password reset for AWS Directory Service AD provider"
                )

                _pw_reset_request = SocaHttpClient(
                    endpoint="/api/user/reset_password",
                    headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
                ).post(
                    data={
                        "user": user,
                        "password": password,
                        "directory_id": config.Config.DIRECTORY_SERVICE_ID,
                    }
                )
                if _pw_reset_request.get("success") is False:
                    _pw_reset_error = f"Unable to set up password for {user} due to {_pw_reset_request.get('message')}"
                    logger.error(_pw_reset_error)
                    logger.info(
                        f"Rolling back user {user} and group {group} due to password failure"
                    )
                    _del_result = _soca_identity_client.delete(dn=_dn_user)
                    if _del_result.get("success"):
                        logger.info(f"Rolled back AD user {_dn_user}")
                    else:
                        logger.error(f"Failed to rollback user {_dn_user}: {_del_result.get('message')}")
                    _group_dn = f"cn={group},{config.Config.DIRECTORY_GROUP_SEARCH_BASE}"
                    _del_grp_result = _soca_identity_client.delete(dn=_group_dn)
                    if _del_grp_result.get("success"):
                        logger.info(f"Rolled back AD group {_group_dn}")
                    else:
                        logger.error(f"Failed to rollback group {_group_dn}: {_del_grp_result.get('message')}")
                    return SocaError.IDENTITY_PROVIDER_ERROR(
                        helper=_pw_reset_error
                    ).as_flask()

            # Option B: nudge sssd to invalidate its cache so the next
            # getpwnam goes straight to AD instead of returning a stale
            # negative-cache entry. Best-effort — failure here is fine,
            # we still have the existing 15-attempt poll as a fallback.
            # Tightens typical-case wait from ~5-15s to ~1-3s.
            #
            # Use subprocess directly: SocaSubprocessClient assumes a
            # shell-string command, which loses argv-list safety. sss_cache
            # is a fixed, hard-coded argv with no user input, so the direct
            # subprocess.run call is correct + simpler here.
            try:
                _sss_flush = subprocess.run(
                    ["sudo", "/usr/sbin/sss_cache", "-E"],
                    capture_output=True, text=True, timeout=5, check=False,
                )
                logger.info(
                    "sss_cache -E flush after AD add: rc=%s",
                    _sss_flush.returncode,
                )
                _telemetry.set("sss_cache_rc", _sss_flush.returncode)
            except Exception as _sss_err:
                logger.warning(
                    "sss_cache -E flush failed (non-fatal): %s", _sss_err,
                )
            _telemetry.mark("sss_cache_ms")

            # wait until the user is fully accessible from sssd
            _user_is_propagated = False
            # Do not rename to `_` -- that shadows the gettext alias.
            for _sssd_attempt in range(15):
                _telemetry.incr("sssd_polls")
                try:
                    pwd.getpwnam(user)
                    _user_is_propagated = True
                    logger.info(f"{user} created on AD and visible on the system")
                    break
                except KeyError:
                    logger.warning(
                        f"{user} created on AD, but not yet visible on the system , waiting ..."
                    )
                    time.sleep(1)
            _telemetry.mark("sssd_visible_ms")

            if not _user_is_propagated:
                logger.error(
                    f"User {user} created but LDAP did not refresh after 15 seconds. Continuing creation process, permissions can still be configured post-user creation"
                )

            logger.info("Creating Home Directory for user")
            if not create_home(user, group, telemetry=_telemetry):
                _telemetry.set("home_dir_status", "fail")
                _telemetry.mark("home_dir_ms")
                _telemetry.emit(cluster_id=_cluster_id, outcome="soft")
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"User created but could not create {user} home directory."
                ).as_flask()
            _telemetry.set("home_dir_status", "ok")
            _telemetry.mark("home_dir_ms")
            logger.info("Home Directory created successfully")

            logger.info("Creating API key for user")
            try:
                SocaHttpClient(
                    endpoint="/api/user/api_key",
                    headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
                ).get(params={"user": user})
            except Exception as err:
                logger.error(
                    f"User created but unable to create API key. SOCA will try to generate it when user log in for the first time {err}"
                )

            if sudoers == 1:
                logger.info(f"Granting Sudo permission to {user}")
                _grant_sudo = SocaHttpClient(
                    endpoint="/api/ldap/sudo",
                    headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
                ).post(data={"user": user})

                if not _grant_sudo.success:
                    _sudo_grant_error = f"Unable to give admin permissions to {user} because of {_grant_sudo.get('message')}"
                    logger.error(_sudo_grant_error)
                    _non_blocking_errors.append(_sudo_grant_error)

                else:
                    logger.info("SUDO Permission granted successfully")
            else:
                logger.info("No SUDO permissions requested for this user")

            logger.info(f"Adding user {user} to group {group}")
            _update_group = SocaHttpClient(
                endpoint="/api/ldap/group",
                headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
            ).put(data={"group": f"{group}", "user": user, "action": "add"})

            if not _update_group.success:
                _grp_update_error = f"Unable to add {user} to {group} because of {_update_group.get('message')}"
                logger.error(_grp_update_error)
                _non_blocking_errors.append(_grp_update_error)
            else:
                logger.info(f"{user} has been added to {group} successfully")
                if config.Config.DIRECTORY_AUTH_PROVIDER in [
                    "aws_ds_managed_activedirectory",
                ]:
                    # Default GroupID point to "Domain Users". We update this to match the group we just have created for the user
                    # Any file created by the user will be owned by <user> : <user_group>
                    _find_group_sid = _soca_identity_client.search(
                        base=config.Config.DIRECTORY_GROUP_SEARCH_BASE,
                        filter=f"(&(objectClass=group)(cn={group}))",
                        attr_list=["objectSid"],
                    )
                    if _find_group_sid.get("success"):
                        _group_sid = _find_group_sid.get("message")[0][1].get(
                            "objectSid"
                        )[0]
                        # Extract the RID from the group SID
                        # The RID is stored in the last 4 bytes of the SID
                        _group_rid = struct.unpack("I", _group_sid[-4:])[0]

                        # Add new primaryGroupID attr for user creation
                        # _attrs.append(("primaryGroupID", [str(_group_rid).encode("utf-8")]))
                        _replace_primary_group_id = _soca_identity_client.modify(
                            _dn_user,
                            [
                                (
                                    ldap.MOD_REPLACE,
                                    "primaryGroupID",
                                    [str(_group_rid).encode("utf-8")],
                                )
                            ],
                        )
                        if _replace_primary_group_id.get("success") is False:
                            _replace_guid_error = f"Unable to set primaryGroupID for user {_dn_user} because of {_replace_primary_group_id.get('message')}"
                            _non_blocking_errors.append(_replace_guid_error)
                            logger.error(_replace_guid_error)
                    else:
                        _find_guid_error = f"Unable to find objectSid for {group} because of {_find_group_sid}"
                        _non_blocking_errors.append(_find_guid_error)
                        logger.error(_find_guid_error)

            if len(_non_blocking_errors) >= 1:
                logger.warning(
                    f"One or more non-blocking errors occurred during user creation: {_non_blocking_errors}"
                )
                _telemetry.emit(cluster_id=_cluster_id, outcome="soft")
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"User created with errors: {_non_blocking_errors}"
                ).as_flask()
            else:
                _telemetry.emit(cluster_id=_cluster_id, outcome="ok")
                return SocaResponse(success=True, message=_("User created")).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            try:
                _telemetry.emit(cluster_id=_cluster_id, outcome="fail")
            except Exception:
                pass
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

    @admin_api
    @feature_flag(flag_name="USERS_GROUPS_MANAGEMENT", mode="api")
    def delete(self):
        """
        Delete user
        ---
        openapi: 3.1.0
        operationId: deleteLdapUser
        tags:
          - User Management
        summary: Delete user
        description: Delete a LDAP user and associated group. Home directory is backed up with timestamp suffix.
        security:
          - socaAuth: []
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - user
                properties:
                  user:
                    type: string
                    description: Username of the user to delete
                    minLength: 1
                    maxLength: 31
                    pattern: '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'
                    example: "john.doe"
        responses:
          '200':
            description: User deleted successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: string
                      example: "Deleted user"
          '203':
            description: User not found
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to delete user, john.doe does not seem to exist"
          '400':
            description: Invalid request or self-deletion attempt
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "You cannot request to delete your own account"
          '500':
            description: Internal server error
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to delete user due to LDAP error"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="form")
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        request_user = request.headers.get("X-EDH-USER")
        if request_user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        if request_user == user:
            return SocaError.GENERIC_ERROR(
                helper="You cannot request to delete your own account"
            ).as_flask()

        _is_user_exist = SocaHttpClient(
            endpoint="/api/ldap/user",
            headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
        ).get(params={"user": user})

        if _is_user_exist.success:
            if len(_is_user_exist.message) != 1:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to delete user, {user} does not seems to exist"
                ).as_flask()
        else:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"Unable to check if user {user} already exist, {_is_user_exist.message}"
            ).as_flask()

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()

            if config.Config.DIRECTORY_AUTH_PROVIDER in [
                "openldap",
                "existing_openldap",
            ]:
                group = f"{args['user']}{config.Config.DIRECTORY_GROUP_NAME_SUFFIX}"
                entries_to_delete = [
                    f"uid={user},{config.Config.DIRECTORY_PEOPLE_SEARCH_BASE}",
                    f"cn={group},{config.Config.DIRECTORY_GROUP_SEARCH_BASE}",
                    f"cn={user},{config.Config.DIRECTORY_ADMIN_SEARCH_BASE}",
                ]
            else:
                group = f"{args['user']}{config.Config.DIRECTORY_GROUP_NAME_SUFFIX}"
                entries_to_delete = [
                    f"cn={user},{config.Config.DIRECTORY_PEOPLE_SEARCH_BASE}",
                    f"cn={group},{config.Config.DIRECTORY_GROUP_SEARCH_BASE}",
                ]

            today = datetime.now(timezone.utc).strftime("%s")
            user_home = config.Config.USER_HOME + "/" + user
            backup_folder = config.Config.USER_HOME + "/" + user + "_" + today
            logger.info(f"Creating backup home folder for {user} -> {backup_folder}")
            try:
                shutil.move(user_home, backup_folder)
                os.chmod(backup_folder, 0o700)
            except Exception as err:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to create backup home folder for {user} due to {err}. Verify if {user_home} exists. Backup folder to be created: {backup_folder}"
                ).as_flask()

            for entry in entries_to_delete:
                _delete_attempt = _soca_identity_client.delete(dn=entry)
                # note: ldap.NO_SUCH_OBJECT will always return success=True.
                # success=False only if the DELETE command was not able to delete an existing object for whatever reasons
                if not _delete_attempt.success:
                    return SocaError.IDENTITY_PROVIDER_ERROR(
                        helper=f"Unable to delete {entry} because of {_delete_attempt.message}"
                    ).as_flask()

            _invalidate_api_key = SocaHttpClient(
                endpoint="/api/user/api_key",
                headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
            ).delete(data={"user": user})
            if _invalidate_api_key.get("success") is False:
                if (
                    f"no active token found for {user}".lower()
                    in _invalidate_api_key.get("message").lower()
                ):
                    logger.info(
                        f"No active token found for {user}. Skipping API key invalidation."
                    )
                else:
                    return SocaError.IDENTITY_PROVIDER_ERROR(
                        helper=f"User {user} deleted but unable to invalidate API key because of {_invalidate_api_key.message}."
                    ).as_flask()

            # Best-effort: drop the deleted user's stored preferences so a
            # future username reuse cannot inherit them (decision #7, primary
            # cleanup). The LDAP delete has already succeeded at this point, so
            # a prefs-store hiccup must NOT fail the user delete -- the
            # reconciliation sweep is the backstop for any miss here.
            try:
                from utils import user_pref_store as _user_prefs

                _user_prefs.clear_all(user)
            except Exception as _pref_err:
                logger.warning(
                    f"user delete: failed to clear preferences for {user}: {_pref_err}"
                )

            return SocaResponse(success=True, message=_("Deleted user")).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()
