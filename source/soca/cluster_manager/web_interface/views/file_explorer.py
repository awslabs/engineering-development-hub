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

import logging
import time

import config
import zipfile
from decorators import login_required, feature_flag
from flask import (
    render_template,
    request,
    redirect,
    session,
    flash,
    Blueprint,
    send_file,
    after_this_request,
    Response,
)
from flask_babel import gettext as _
import errno
import io
import math
import os
import stat
import tempfile
import base64
import secrets
import shutil
from cryptography.fernet import Fernet, MultiFernet, InvalidToken, InvalidSignature
import json
import pwd
from collections import OrderedDict
from flask import Flask
from werkzeug.utils import secure_filename
from cachetools import TTLCache
from datetime import datetime, timezone
from utils.config import SocaConfig
from utils.cast import SocaCastEngine
from utils.http_client import SocaHttpClient
from utils.user_filesystems_acls import check_user_permission, Permissions
import pathlib

logger = logging.getLogger("soca_logger")
file_explorer = Blueprint("file_explorer", __name__, template_folder="templates")
app = Flask(__name__)

# Set up caching
with app.app_context():
    cache = TTLCache(
        maxsize=10000, ttl=config.Config.DEFAULT_CACHE_TIME
    )  # default is 120 seconds

CACHE_FOLDER_CONTENT_PREFIX = "file_explorer_folder_content_"


def _cluster_id() -> str:
    """ClusterId from SocaConfig, guarded on .success per the client-wrapper contract."""
    _cfg = SocaConfig(key="/configuration/ClusterId").get_value()
    return _cfg.get("message", "unknown") if _cfg.get("success") else "unknown"


def change_ownership(file_path: str) -> dict:
    """Atomically chown+chmod via fd to eliminate TOCTOU symlink races."""
    if not file_path:
        return {"success": False, "message": "Invalid file path"}

    user_info = pwd.getpwnam(session["user"])
    uid = user_info.pw_uid
    gid = user_info.pw_gid

    # O_NOFOLLOW rejects symlinks; O_NONBLOCK prevents a FIFO from blocking the open.
    try:
        fd = os.open(file_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as err:
        if err.errno == errno.ELOOP:
            logger.warning(f"change_ownership: refusing to follow symlink at {file_path}")
            return {"success": False, "message": "Refusing to follow symlink"}
        logger.warning(f"change_ownership: cannot open {file_path}: {err}")
        return {"success": False, "message": "File not found"}

    try:
        _st = os.fstat(fd)
        if not (stat.S_ISREG(_st.st_mode) or stat.S_ISDIR(_st.st_mode)):
            logger.warning(f"change_ownership: refusing non-regular/non-dir file at {file_path}")
            return {"success": False, "message": "Refusing to operate on special file"}
        os.fchown(fd, uid, gid)
        _desired_mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP
        if stat.S_ISDIR(_st.st_mode):
            _desired_mode |= stat.S_IXUSR | stat.S_IXGRP
        os.fchmod(fd, _desired_mode)
    finally:
        os.close(fd)

    return {"success": True, "message": "Permission updated correctly"}


def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    if size_bytes <= 1000:
        return f"{size_bytes}B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])


def _token_cipher():
    """MultiFernet from the SM encryption ring: encrypts with current, decrypts across current+previous (rotation-safe)."""
    _cur, _prev = config.Config._SESSION_ENCRYPTION_KEYS
    return MultiFernet([Fernet(_cur)] + ([Fernet(_prev)] if _prev else []))


def encrypt(file_path, file_size):
    try:
        cipher_suite = _token_cipher()
        payload = {
            "file_owner": session["user"],
            "file_path": file_path,
            "file_size": file_size,
        }
        encrypted_text = cipher_suite.encrypt(json.dumps(payload).encode("utf-8"))
        return {"success": True, "message": encrypted_text.decode()}
    except Exception as _err:
        return {"success": False, "message": "UNABLE_TO_GENERATE_TOKEN"}


def decrypt(encrypted_text):
    try:
        cipher_suite = _token_cipher()
        decrypted_text = cipher_suite.decrypt(encrypted_text.encode())
        return {"success": True, "message": decrypted_text}
    except InvalidToken:
        return {"success": False, "message": "Invalid Token"}
    except InvalidSignature:
        return {"success": False, "message": "Invalid Signature"}
    except Exception as _err:
        return {"success": False, "message": str(_err)}


def demote(user_uid, user_gid):
    def set_ids():
        os.setgid(user_gid)
        os.setuid(user_uid)

    return set_ids


def resolve_file(uid):
    """
    Shared UID -> file resolver used by anything that accepts a
    file_explorer encrypted UID (tail, editor, future callers).

    Steps:
      1. Decrypt the UID and parse file_path / file_owner.
      2. Verify the current session user matches file_owner (anti-forgery).
      3. Check POSIX read permission via check_user_permission().
      4. Verify the path is a regular file that exists.
      5. stat() for size.

    Does NOT enforce any size cap -- callers apply their own limit on the
    returned `size` field since different features have different caps
    (tail rejects >1 GB, editor rejects >1 MB, etc.).

    Returns (info, None) on success where info is
    {"path": str, "size": int, "owner": str},
    or (None, error_message) on failure. Error messages are user-facing
    and deliberately non-disambiguating so we don't leak whether the
    failure was "wrong user" vs "no permission" vs "doesn't exist".
    """
    if not uid:
        return None, _("Missing file identifier")

    decrypted = decrypt(uid)
    if not decrypted.get("success"):
        return None, _("Invalid file identifier")

    try:
        file_info = json.loads(decrypted["message"])
    except (TypeError, ValueError):
        return None, _("Malformed file identifier")

    file_path = file_info.get("file_path", "")
    file_owner = file_info.get("file_owner", "")

    current_user = session.get("user")
    if not current_user or current_user != file_owner:
        logger.warning(
            "resolve_file: user '%s' attempted to access file owned by '%s'",
            current_user, file_owner,
        )
        return None, _("You are not authorized to access this file")

    if check_user_permission(
        path=file_path,
        permissions=Permissions.READ,
        user=current_user,
    ) is False:
        return None, _("You do not have permission to read this file")

    if not os.path.isfile(file_path):
        return None, _("File does not exist or is not a regular file")

    try:
        file_size = os.path.getsize(file_path)
    except OSError as err:
        logger.warning("resolve_file: stat() failed on %s: %s", file_path, err)
        return None, _("Unable to stat file")

    return {"path": file_path, "size": file_size, "owner": file_owner}, None


def _transfer_engine():
    """Active file transfer engine: 'v1' (Dropzone + native download) or 'v2' (Uppy/tus + parallel). Runtime-flippable via /configuration/FileBrowser/TransferEngine."""
    _v = (
        SocaConfig(key="/configuration/FileBrowser/TransferEngine")
        .get_value(default="v1", allow_unknown_key=True)
        .get("message")
    )
    return "v2" if _v == "v2" else "v1"


@file_explorer.route("/file_explorer", methods=["GET"])
@login_required
@feature_flag(flag_name="FILE_BROWSER", mode="view")
def index():
    try:
        path = request.args.get("path")
        path = path or f"{config.Config.USER_HOME}/{session.get('user')}"

        path = pathlib.Path(path).resolve()

        timestamp = datetime.now(timezone.utc).strftime("%s")
        ts = request.args.get("ts", None)

        if ts is None:
            if path is None:
                return redirect(f"/file_explorer?ts={timestamp}")
            else:
                return redirect(f"/file_explorer?path={path}&ts={timestamp}")

        filesystem = {}
        breadcrumb = {}

        if (
            check_user_permission(
                path=path,
                permissions=Permissions.READ,
                user=session.get("user", None),
                paths_to_restrict=config.Config.PATH_TO_RESTRICT,
            )
            is False
        ):
            if path == f"{config.Config.USER_HOME}/{session['user']}":
                flash(_("SOCA cannot access your home directory. Please ask an admin to set your folder ACLs to 750"))
                return redirect("/")
            else:
                flash(_(
                    "You are not authorized to access this location and/or this path is restricted by the Administrator. If you recently changed the permissions, please allow up to 10 minutes for sync."),
                    "error",
                )
                return redirect("/file_explorer")

        # Build breadcrumb
        count = 1
        for level in str(path).split("/"):
            if level == "":
                breadcrumb["/"] = "root"
            else:
                breadcrumb["/".join(str(path).split("/")[:count])] = level

            count += 1

        # Retrieve files/folders
        if CACHE_FOLDER_CONTENT_PREFIX + str(path) not in cache.keys():
            is_cached = False
            logger.debug(f"Cache miss for {path=}")
            try:
                for entry in os.scandir(path):
                    if not entry.name.startswith("."):
                        try:
                            filesystem[entry.name] = {
                                "path": f"{path}/{entry.name}",
                                "uid": encrypt(
                                    f"{path}/{entry.name}", entry.stat().st_size
                                )["message"],
                                "type": "folder" if entry.is_dir() else "file",
                                "st_size": convert_size(entry.stat().st_size),
                                "st_size_default": entry.stat().st_size,
                                "st_mtime": entry.stat().st_mtime,
                            }
                        except Exception as err:
                            # most likely symbolic link pointing to wrong location
                            flash(_("{entry.name} returned an error and cannot be displayed: {err}"))
                cache[CACHE_FOLDER_CONTENT_PREFIX + str(path)] = filesystem

            except OSError as err:
                if err.errno == errno.EPERM:
                    flash(_(
                        "Sorry we could not access this location due to a permission error. If you recently changed the permissions, please allow up to 10 minutes for sync."),
                        "error",
                    )
                elif err.errno == errno.ENOENT:
                    flash(_("Could not locate the directory. Did you delete it ?"), "error")
                else:
                    flash(_("Could not locate the directory: ") + str(err), "error")
                return redirect("/file_explorer")
            except Exception as err:
                logger.error(f"Unable to access directory due to {err}")
                flash(_("Could not locate the directory: ") + str(err), "error")
                return redirect("/file_explorer")
        else:
            logger.debug(f"Cache hit for {path}")
            is_cached = True
            filesystem = cache[CACHE_FOLDER_CONTENT_PREFIX + str(path)]

        get_all_uid = [
            file_info["uid"]
            for file_info in filesystem.values()
            if file_info["type"] == "file"
        ]

        _login_nodes_endpoint = (
        SocaConfig(key="/configuration/NLBLoadBalancerDNSName")
        .get_value()
        .get("message")
    )

        _path_cast = SocaCastEngine(path).cast_as(str)
        _path_str = _path_cast.get("message") if _path_cast.get("success") is True else ""

        return render_template(
            "file_explorer.html",
            filesystem=OrderedDict(
                sorted(filesystem.items(), key=lambda t: t[0].lower())
            ),
            get_all_uid=base64.b64encode(",".join(get_all_uid).encode()).decode(),
            get_all_uid_count=len(get_all_uid),
            breadcrumb=breadcrumb,
            max_upload_size=config.Config.MAX_UPLOAD_FILE,
            max_upload_timeout=config.Config.MAX_UPLOAD_TIMEOUT,
            max_online_preview=config.Config.MAX_SIZE_ONLINE_PREVIEW,
            default_cache_time=config.Config.DEFAULT_CACHE_TIME,
            path=_path_str,
            page="file_explorer",
            is_cached=is_cached,
            timestamp=timestamp,
            login_nodes_endpoint=_login_nodes_endpoint,
            user=session.get("user", ""),
            user_token=session.get("api_key", ""),
            transfer_engine=_transfer_engine(),
        )
    except Exception as err:
        flash(_("Error, this path probably does not exist. ") + str(err), "error")
        logger.error(err)
        return redirect("/file_explorer")


@file_explorer.route("/file_explorer/download", methods=["GET"])
@login_required
@feature_flag(flag_name="FILE_BROWSER", mode="view")
def download():
    uid = request.args.get("uid", None)
    if uid is None:
        return redirect("/file_explorer")
    allow_download = config.Config.ALLOW_DOWNLOAD_FROM_PORTAL
    if allow_download is not True:
        flash(_("Download file is disabled. Please contact your cluster administrator"))
        return redirect("/file_explorer")

    files_to_download = uid.split(",")
    if len(files_to_download) == 1:
        file_information = decrypt(files_to_download[0])
        if file_information["success"] is True:
            file_info = json.loads(file_information["message"])
            if (
                check_user_permission(
                    path=file_info.get("file_path", ""),
                    permissions=Permissions.READ,
                    user=session.get("user", None),
                )
                is False
            ):
                flash(_("You are not authorized to download this file or this file is no longer available on the filesystem"))
                return redirect("/file_explorer")

            current_user = session["user"]
            if current_user == file_info["file_owner"]:
                try:
                    # Atomic open; O_NOFOLLOW closes the validate->read symlink TOCTOU, O_NONBLOCK avoids a FIFO block.
                    _path = file_info.get("file_path", "")
                    _fd = os.open(_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    _st = os.fstat(_fd)
                    if not stat.S_ISREG(_st.st_mode):
                        os.close(_fd)
                        logger.warning(f"download: refusing non-regular file at {_path}")
                        flash(_("Not a regular file"), "error")
                        return redirect("/file_explorer")
                    _fobj = io.FileIO(_fd, closefd=True)
                    return send_file(
                        _fobj,
                        as_attachment=True,
                        download_name=_path.split("/")[-1],
                        conditional=True,
                    )
                except OSError as err:
                    if err.errno == errno.ELOOP:
                        flash(_("Refusing to follow symlink"), "error")
                    else:
                        flash(_("Unable to download file. Did you remove it?"), "error")
                    return redirect("/file_explorer")
            else:
                flash(_("You do not have the permission to download this file"), "error")
                return redirect("/file_explorer")

        else:
            flash(_("Unable to download ") + file_information.get("message"), "error")
            return redirect("/file_explorer")
    else:
        valid_file_path = []
        total_size = 0
        total_files = 0
        for file_to_download in files_to_download:
            file_information = decrypt(file_to_download)
            if file_information["success"] is True:
                file_info = json.loads(file_information["message"])
                if (
                    check_user_permission(
                        path=file_info["file_path"],
                        permissions=Permissions.READ,
                        user=session.get("user", None),
                    )
                    is False
                ):
                    flash(_("You are not authorized to download this file or this file is no longer available on the filesystem"))
                    return redirect("/file_explorer")

                current_user = session["user"]
                if current_user == file_info["file_owner"]:
                    valid_file_path.append(file_info["file_path"])
                    total_size = total_size + file_info["file_size"]
                    total_files = total_files + 1

        if total_size > config.Config.MAX_ARCHIVE_SIZE:
            flash(
                _("Sorry, the maximum archive size is {max_size:.2f} MB. Your archive was {actual_size:.2f} MB. To avoid this issue, you can create a smaller archive, download files individually, use SFTP or edit the maximum archive size authorized.").format(
                    max_size=config.Config.MAX_ARCHIVE_SIZE / 1024 / 1024,
                    actual_size=total_size / 1024 / 1024,
                ),
                "error",
            )
            return redirect("/file_explorer")

        # Limit HTTP payload size
        if total_files > 45:
            flash(_(
                f"Sorry, you cannot download more than 45 files in a single call. Your archive contained {total_files} files"),
                "error",
            )
            return redirect("/file_explorer")

        if valid_file_path.__len__() == 0:
            return redirect("/file_explorer")

        ts = datetime.now(timezone.utc).strftime("%s")
        _zip_dir = os.path.join(_get_zip_staging_dir(), _cluster_id(), session['user'])
        os.makedirs(_zip_dir, mode=0o700, exist_ok=True)
        _fd, archive_name = tempfile.mkstemp(
            suffix=".zip", prefix=f"EDH_Download_{ts}_", dir=_zip_dir
        )
        os.close(_fd)

        zipf = zipfile.ZipFile(archive_name, "w", zipfile.ZIP_DEFLATED)
        logger.info(
            "About to create archive: "
            + str(archive_name)
            + " with the following files: "
            + str(valid_file_path)
        )
        try:
            for file_to_zip in valid_file_path:
                zipf.write(file_to_zip)
            zipf.close()
            logger.info("Archive created")
        except Exception as err:
            logger.error("Unable to create archive due to: " + str(err))
            try:
                os.remove(archive_name)
            except OSError:
                pass
            flash(_(
                "Unable to generate download link. Check the logs for more information"),
                "error",
            )
            return redirect("/file_explorer")

        if os.path.exists(archive_name):
            @after_this_request
            def _cleanup_zip(response):
                try:
                    os.remove(archive_name)
                except OSError:
                    pass
                return response
            return send_file(
                archive_name,
                mimetype="zip",
                download_name=archive_name.split("/")[-1],
                as_attachment=True,
            )
        else:
            flash(_("Unable to locate the download archive, please try again"), "error")
            logger.error("Unable to locate " + str(archive_name))
            return redirect("/file_explorer")


@file_explorer.route("/file_explorer/download_all", methods=["GET"])
@login_required
@feature_flag(flag_name="FILE_BROWSER", mode="view")
def download_all():
    path = request.args.get("path", "")
    if not path:
        return redirect("/file_explorer")
    allow_download = config.Config.ALLOW_DOWNLOAD_FROM_PORTAL
    if allow_download is not True:
        flash(_(" Download file is disabled. Please contact your SOCA cluster administrator"))
        return redirect("/file_explorer")
    filesystem = {}
    try:
        for entry in os.scandir(path):
            if not entry.name.startswith("."):
                if entry.is_dir():
                    # Ignore folder. We only include files
                    pass
                else:
                    filesystem[entry.name] = {
                        "path": path + "/" + entry.name,
                        "uid": encrypt(path + "/" + entry.name, entry.stat().st_size)[
                            "message"
                        ],
                        "type": "file",
                        "st_size": convert_size(entry.stat().st_size),
                        "st_size_default": entry.stat().st_size,
                        "st_mtime": entry.stat().st_mtime,
                    }

    except Exception as err:
        if err.errno == errno.EPERM:
            flash(_(
                "Sorry we could not access this location due to a permission error. If you recently changed the permissions, please allow up to 10 minutes for sync."),
                "error",
            )
        elif err.errno == errno.ENOENT:
            flash(_("Could not locate the directory. Did you delete it ?"), "error")
        else:
            flash(_("Could not locate the directory: ") + str(err), "error")
        return redirect("/file_explorer")

    valid_file_path = []
    total_size = 0
    total_files = 0
    for file_name, file_info in filesystem.items():
        if (
            check_user_permission(
                path=file_info["path"],
                permissions=Permissions.READ,
                user=session.get("user"),
            )
            is False
        ):
            flash(_("You are not authorized to download some files (double check if your user own ALL files in this directory)."))
            return redirect("/file_explorer")

        valid_file_path.append(file_info["path"])
        total_size = total_size + file_info["st_size_default"]
        total_files = total_files + 1

    if total_size > config.Config.MAX_ARCHIVE_SIZE:
        flash(_(
            "Sorry, the maximum archive size is {:.2f} MB. Your archive was {:.2f} MB. To avoid this issue, you can create a smaller archive, download files individually, use SFTP or edit the maximum archive size authorized.").format(
                config.Config.MAX_ARCHIVE_SIZE / 1024 / 1024, total_size / 1024 / 1024
            ),
            "error",
        )
        return redirect("/file_explorer")

    if valid_file_path.__len__() == 0:
        return redirect("/file_explorer")

    ts = datetime.now(timezone.utc).strftime("%s")
    _zip_dir = os.path.join(_get_zip_staging_dir(), _cluster_id(), session['user'])
    os.makedirs(_zip_dir, mode=0o700, exist_ok=True)
    _fd, archive_name = tempfile.mkstemp(
        suffix=".zip", prefix=f"EDH_Download_{ts}_", dir=_zip_dir
    )
    os.close(_fd)
    zipf = zipfile.ZipFile(archive_name, "w", zipfile.ZIP_DEFLATED)
    logger.info(
        "About to create archive: "
        + str(archive_name)
        + " with the following files: "
        + str(valid_file_path)
    )
    try:
        for file_to_zip in valid_file_path:
            zipf.write(file_to_zip)
        zipf.close()
        logger.info("Archive created")
    except Exception as err:
        logger.error("Unable to create archive due to: " + str(err))
        try:
            os.remove(archive_name)
        except OSError:
            pass
        flash(_(
            "Unable to generate download link. Check the logs for more information"),
            "error",
        )
        return redirect("/file_explorer")

    if os.path.exists(archive_name):
        @after_this_request
        def _cleanup_zip(response):
            try:
                os.remove(archive_name)
            except OSError:
                pass
            return response
        return send_file(
            archive_name,
            mimetype="zip",
            download_name=archive_name.split("/")[-1],
            as_attachment=True,
        )
    else:
        flash(_("Unable to locate the download archive, please try again"), "error")
        logger.error("Unable to locate " + str(archive_name))
        return redirect("/file_explorer")


@file_explorer.route("/file_explorer/upload", methods=["POST"])
@login_required
@feature_flag(flag_name="FILE_BROWSER", mode="view")
def upload():
    path = request.form.get("path", "")
    file_list = request.files.getlist("file")
    if not path:
        return redirect("/file_explorer")
    if not file_list:
        return redirect("/file_explorer")
    if (
        check_user_permission(
            path=path, permissions=Permissions.WRITE, user=session.get("user", "")
        )
        is False
    ):
        flash(_("You are not authorized to upload in this location ({path}). If you recently changed the permissions, please allow up to 10 minutes for sync"))
        return "Unauthorized", 401
    for file in file_list:
        try:
            destination = path + secure_filename(file.filename)
            if (
                CACHE_FOLDER_CONTENT_PREFIX + path[:-1] in cache.keys()
            ):  # remove  trailing slash
                del cache[CACHE_FOLDER_CONTENT_PREFIX + path[:-1]]
            file.save(destination)
            change_ownership(destination)
        except Exception as err:
            return str(err), 500
    return "Success", 200


# --- Resumable upload: Flask-native tus 1.0.0 subset (creation extension) ---
TUS_RESUMABLE = "1.0.0"
TUS_EXTENSIONS = "creation,concatenation,termination"

# Default staging paths (used when SocaConfig keys are absent or unset)
_DEFAULT_UPLOADS_TMP = str(pathlib.Path(__file__).resolve().parent.parent / "tmp" / "uploads")
_DEFAULT_ZIP_TMP = "tmp/zip_downloads"  # relative to app root, resolved at call time


def _get_staging_dir() -> str:
    """Return the tus partial-upload staging directory (configurable via SocaConfig)."""
    _cfg = SocaConfig(key="/configuration/FileBrowser/StagingDirectory").get_value()
    if _cfg.get("success"):
        _val = (_cfg.get("message") or "").strip()
        if _val:
            return _val
    return _DEFAULT_UPLOADS_TMP


def _get_zip_staging_dir() -> str:
    """Return the zip download staging directory (configurable via SocaConfig)."""
    _cfg = SocaConfig(key="/configuration/FileBrowser/ZipStagingDirectory").get_value()
    if _cfg.get("success"):
        _val = (_cfg.get("message") or "").strip()
        if _val:
            return _val
    # Legacy default: /opt/edh/<cluster>/cluster_manager/web_interface/tmp/zip_downloads
    _cluster = _cluster_id()
    return f"/opt/edh/{_cluster}/cluster_manager/web_interface/{_DEFAULT_ZIP_TMP}"


def _tus_headers(extra=None):
    """Base tus response headers."""
    _h = {"Tus-Resumable": TUS_RESUMABLE, "Cache-Control": "no-store"}
    if extra:
        _h.update(extra)
    return _h


def _tus_encode(payload):
    """Encrypt the upload descriptor into an opaque, URL-safe token."""
    return _token_cipher().encrypt(json.dumps(payload).encode("utf-8")).decode()


def _tus_decode(token):
    """Decrypt an upload token; returns dict or None."""
    try:
        return json.loads(_token_cipher().decrypt(token.encode()).decode("utf-8"))
    except (InvalidToken, InvalidSignature, ValueError, TypeError):
        return None


def _parse_upload_metadata(header_value):
    """Parse tus Upload-Metadata (comma-separated 'key b64value' pairs)."""
    _meta = {}
    if not header_value:
        return _meta
    for _pair in header_value.split(","):
        _parts = _pair.strip().split(" ")
        if not _parts[0]:
            continue
        if len(_parts) > 1:
            try:
                _meta[_parts[0]] = base64.b64decode(_parts[1]).decode("utf-8")
            except Exception:
                _meta[_parts[0]] = ""
        else:
            _meta[_parts[0]] = ""
    return _meta


def _tus_concat_final(concat_header):
    """tus concatenation: merge referenced partial uploads (in order) into the final file."""
    _user = session.get("user", "")
    _meta = _parse_upload_metadata(request.headers.get("Upload-Metadata", ""))
    _filename = secure_filename(_meta.get("filename", ""))
    _target_dir = _meta.get("path", "")
    if not _filename or not _target_dir:
        return Response("Missing filename or path", status=400, headers=_tus_headers())
    if check_user_permission(path=_target_dir, permissions=Permissions.WRITE, user=_user) is False:
        return Response("Forbidden", status=403, headers=_tus_headers())

    _spec = concat_header.split(";", 1)[1].strip() if ";" in concat_header else ""
    _urls = [_u for _u in _spec.split() if _u]
    if not _urls:
        return Response("No partial uploads referenced", status=400, headers=_tus_headers())

    # resolve + authorize each partial, in the order the client listed them
    _staging_paths = []
    for _u in _urls:
        _tok = _u.rstrip("/").split("/")[-1]
        _pi = _tus_decode(_tok)
        if not _pi or _pi.get("o") != _user or _pi.get("c") != "partial":
            return Response("Invalid partial reference", status=400, headers=_tus_headers())
        _sp = os.path.join(_pi["d"], _pi["p"])
        if not os.path.isfile(_sp):
            return Response("Partial not found", status=404, headers=_tus_headers())
        _staging_paths.append(_sp)

    _final = os.path.join(_target_dir, _filename)
    try:
        # O_NOFOLLOW refuses to write through a symlink swapped in after the parent-dir permission check (uwsgi runs as root).
        _out_fd = os.open(_final, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        with os.fdopen(_out_fd, "wb") as _out:
            for _sp in _staging_paths:
                with open(_sp, "rb") as _in:
                    shutil.copyfileobj(_in, _out, 4 * 1024 * 1024)
            # chown/chmod on the still-open fd -- no path re-resolution, no symlink-swap window.
            _uinfo = pwd.getpwnam(_user)
            os.fchown(_out.fileno(), _uinfo.pw_uid, _uinfo.pw_gid)
            os.fchmod(_out.fileno(), stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
        _total = os.path.getsize(_final)
    except OSError as _err:
        logger.error(f"tus concat: merge failed into {_final}: {_err}")
        return Response("Concat failed", status=500, headers=_tus_headers())

    for _sp in _staging_paths:
        try:
            os.remove(_sp)
        except OSError:
            pass
    _ck = CACHE_FOLDER_CONTENT_PREFIX + _target_dir
    if _ck in cache.keys():
        del cache[_ck]

    _fin_token = _tus_encode({"d": _target_dir, "f": _filename, "l": _total, "o": _user, "p": "", "c": "final-done"})
    return Response(status=201, headers=_tus_headers({
        "Location": f"/file_explorer/tus/{_fin_token}",
        "Upload-Offset": str(_total),
    }))


@file_explorer.route("/file_explorer/tus", methods=["POST", "OPTIONS"])
@login_required
@feature_flag(flag_name="FILE_BROWSER", mode="view")
def tus_create():
    """tus creation: reserve a staging .part in the target dir, return its token."""
    _max_bytes = config.Config.MAX_UPLOAD_FILE * 1024 * 1024
    if request.method == "OPTIONS":
        return Response(status=204, headers=_tus_headers({
            "Tus-Version": TUS_RESUMABLE,
            "Tus-Extension": TUS_EXTENSIONS,
            "Tus-Max-Size": str(_max_bytes),
        }))

    # tus (resumable/parallel upload) is the v2 transfer engine only. On v1 the
    # UI serves the classic Dropzone POST /file_explorer/upload path instead.
    if _transfer_engine() != "v2":
        return Response("Resumable upload is not enabled on this cluster.", status=403, headers=_tus_headers({}))

    _concat = request.headers.get("Upload-Concat", "")
    if _concat.startswith("final"):
        return _tus_concat_final(_concat)
    _is_partial = _concat.strip() == "partial"

    try:
        _length = int(request.headers.get("Upload-Length", ""))
    except (TypeError, ValueError):
        return Response("Invalid Upload-Length", status=400, headers=_tus_headers())
    if _length < 0 or _length > _max_bytes:
        return Response("Upload too large", status=413, headers=_tus_headers())

    _user = session.get("user", "")
    _part_name = f".edh-upload-{secrets.token_hex(8)}.part"

    # Partial uploads (parallelUploads) carry no filename/path metadata -- that
    # rides on the final concat request. Stage partials in a per-user temp dir;
    # the real write-permission is enforced at concat time against the target.
    if _is_partial:
        _cluster = _cluster_id()
        _uploads_tmp = os.path.join(_get_staging_dir(), _cluster, _user)
        os.makedirs(_uploads_tmp, mode=0o700, exist_ok=True)
        _staging = os.path.join(_uploads_tmp, _part_name)
        try:
            _fd = os.open(_staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(_fd)
        except OSError as _err:
            logger.error(f"tus_create: cannot create partial staging {_staging}: {_err}")
            return Response("Cannot create upload", status=500, headers=_tus_headers())
        _token = _tus_encode({"d": _uploads_tmp, "f": "", "l": _length, "o": _user, "p": _part_name, "c": "partial"})
        return Response(status=201, headers=_tus_headers({
            "Location": f"/file_explorer/tus/{_token}", "Upload-Offset": "0",
        }))

    # Whole-file (non-parallel) upload: metadata present, stage in the target dir.
    _meta = _parse_upload_metadata(request.headers.get("Upload-Metadata", ""))
    _filename = secure_filename(_meta.get("filename", ""))
    _target_dir = _meta.get("path", "")
    if not _filename or not _target_dir:
        return Response("Missing filename or path", status=400, headers=_tus_headers())
    if check_user_permission(path=_target_dir, permissions=Permissions.WRITE, user=_user) is False:
        return Response("Forbidden", status=403, headers=_tus_headers())

    _staging = os.path.join(_target_dir, _part_name)
    try:
        _fd = os.open(_staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(_fd)
    except OSError as _err:
        logger.error(f"tus_create: cannot create staging {_staging}: {_err}")
        return Response("Cannot create upload", status=500, headers=_tus_headers())

    _token = _tus_encode({"d": _target_dir, "f": _filename, "l": _length, "o": _user, "p": _part_name, "c": ""})
    return Response(status=201, headers=_tus_headers({
        "Location": f"/file_explorer/tus/{_token}", "Upload-Offset": "0",
    }))


@file_explorer.route("/file_explorer/tus/<token>", methods=["HEAD", "PATCH", "OPTIONS", "DELETE"])
@login_required
@feature_flag(flag_name="FILE_BROWSER", mode="view")
def tus_patch(token):
    """tus HEAD (report offset), PATCH (append/finalize), DELETE (terminate)."""
    if request.method == "OPTIONS":
        return Response(status=204, headers=_tus_headers({
            "Tus-Version": TUS_RESUMABLE, "Tus-Extension": TUS_EXTENSIONS,
        }))

    _info = _tus_decode(token)
    if not _info:
        return Response("Invalid upload token", status=404, headers=_tus_headers())
    _user = session.get("user", "")
    if _user != _info.get("o"):
        return Response("Forbidden", status=403, headers=_tus_headers())

    if request.method == "DELETE":
        _sp = os.path.join(_info["d"], _info["p"]) if _info.get("p") else ""
        if _sp and os.path.isfile(_sp):
            try:
                os.remove(_sp)
            except OSError:
                pass
        return Response(status=204, headers=_tus_headers())

    # a completed concatenation target has no staging file; report it complete
    if _info.get("c") == "final-done":
        _len = int(_info["l"])
        return Response(status=(200 if request.method == "HEAD" else 204),
                        headers=_tus_headers({"Upload-Offset": str(_len), "Upload-Length": str(_len)}))

    _staging = os.path.join(_info["d"], _info["p"])
    _length = int(_info["l"])
    try:
        _offset = os.path.getsize(_staging) if os.path.isfile(_staging) else 0
    except OSError:
        _offset = 0

    if request.method == "HEAD":
        return Response(status=200, headers=_tus_headers({
            "Upload-Offset": str(_offset), "Upload-Length": str(_length),
        }))

    # PATCH
    if request.headers.get("Content-Type", "") != "application/offset+octet-stream":
        return Response("Invalid Content-Type", status=415, headers=_tus_headers())
    try:
        _req_offset = int(request.headers.get("Upload-Offset", ""))
    except (TypeError, ValueError):
        return Response("Invalid Upload-Offset", status=400, headers=_tus_headers())
    if _req_offset != _offset:
        return Response("Offset conflict", status=409, headers=_tus_headers({"Upload-Offset": str(_offset)}))
    # re-authorize write on every chunk for whole-file uploads (resume must not
    # bypass authz). Partials live in the root-owned server temp dir; their real
    # authz is the owner-bound token plus the WRITE check enforced at concat time.
    if _info.get("c") != "partial":
        if check_user_permission(path=_info["d"], permissions=Permissions.WRITE, user=_user) is False:
            return Response("Forbidden", status=403, headers=_tus_headers())

    _written = _offset
    try:
        _fd = os.open(_staging, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        with os.fdopen(_fd, "ab", closefd=True) as _fh:
            while True:
                _chunk = request.stream.read(1024 * 1024)
                if not _chunk:
                    break
                _fh.write(_chunk)
                _written += len(_chunk)
                if _written > _length:
                    break
    except OSError as _err:
        logger.error(f"tus_patch: write failed on {_staging}: {_err}")
        return Response("Write failed", status=500, headers=_tus_headers({"Upload-Offset": str(_written)}))

    # Client sent more than it declared in Upload-Length: reject and discard the
    # staging file so an over-declared body can't be finalized or concatenated.
    if _written > _length:
        try:
            os.remove(_staging)
        except OSError:
            pass
        return Response("Upload exceeds declared length", status=413, headers=_tus_headers())

    if _written >= _length and _info.get("c") != "partial":
        _final = os.path.join(_info["d"], _info["f"])
        try:
            os.replace(_staging, _final)  # same-filesystem atomic move, no copy
            change_ownership(_final)
            _ck = CACHE_FOLDER_CONTENT_PREFIX + _info["d"]
            if _ck in cache.keys():
                del cache[_ck]
        except OSError as _err:
            logger.error(f"tus_patch: finalize failed {_staging} -> {_final}: {_err}")
            return Response("Finalize failed", status=500, headers=_tus_headers({"Upload-Offset": str(_written)}))

    return Response(status=204, headers=_tus_headers({"Upload-Offset": str(_written)}))


@file_explorer.route("/file_explorer/create_folder", methods=["POST"])
@login_required
@feature_flag(flag_name="FILE_BROWSER", mode="view")
def create():
    if "folder_name" not in request.form.keys() or "path" not in request.form.keys():
        return redirect("/file_explorer")
    folder_name = request.form.get("folder_name", "")
    folder_path = request.form.get("path", "")
    if not folder_path or not folder_name:
        logger.error(f"{folder_path=} or {folder_name=} are not set")
        return redirect("/file_explorer")

    folder_to_create = pathlib.Path(f"{folder_path}/{folder_name}")
    folder_location = folder_to_create.parent
    try:
        logger.info(f"About to create {folder_to_create=}")
        if (
            check_user_permission(
                path=folder_location,
                permissions=Permissions.WRITE,
                user=session.get("user", ""),
            )
            is False
        ):
            flash(_(
                f"You do not have write permission on {folder_location=} If you recently changed the permissions, please allow up to 10 minutes for sync."),
                "error",
            )
            return redirect(f"/file_explorer?path={folder_path}")

        access_right = 0o750
        os.makedirs(folder_to_create, access_right)
        change_ownership(folder_to_create)
        if CACHE_FOLDER_CONTENT_PREFIX + folder_path[:-1] in cache.keys():
            del cache[CACHE_FOLDER_CONTENT_PREFIX + folder_path[:-1]]
        flash(_(f"{folder_to_create} created successfully."), "success")
    except OSError as err:
        if err.errno == errno.EEXIST:
            flash(_("This folder already exist, choose a different name"), "error")
        else:
            flash(_(
                f"Unable to create: {folder_to_create}. Check logs for more details.{str(err.errno)}"),
                "error",
            )
            logger.error(f"Unable to create: {folder_to_create}. {str(err.errno)}")

    except Exception as err:
        logger.error(err)
        flash(_(f"Unable to create: {folder_to_create}"), "error")

    return redirect(f"/file_explorer?path={folder_path}")


@file_explorer.route("/file_explorer/delete", methods=["GET"])
@login_required
@feature_flag(flag_name="FILE_BROWSER", mode="view")
def delete():
    uid = request.args.get("uid", "")
    if not uid:
        return redirect("/file_explorer")

    file_information = decrypt(uid)
    if file_information["success"] is True:
        file_info = json.loads(file_information["message"])
        try:
            if os.path.isfile(file_info["file_path"]):
                if (
                    check_user_permission(
                        path=file_info.get("file_path", ""),
                        permissions=Permissions.WRITE,
                        user=session.get("user", ""),
                    )
                    is True
                ):
                    os.remove(file_info["file_path"])
                    if (
                        CACHE_FOLDER_CONTENT_PREFIX
                        + "/".join(file_info["file_path"].split("/")[:-1])
                        in cache.keys()
                    ):
                        del cache[
                            CACHE_FOLDER_CONTENT_PREFIX
                            + "/".join(file_info["file_path"].split("/")[:-1])
                        ]
                    flash(_("File removed"), "success")
                else:
                    flash(_(
                        "You do not have the permission to delete this file. If you recently changed the permissions, please allow up to 10 minutes for sync."),
                        "error",
                    )

            elif os.path.isdir(file_info["file_path"]):
                files_in_folder = [
                    f
                    for f in os.listdir(file_info["file_path"])
                    if not f.startswith(".")
                ]
                if len(files_in_folder) == 0:
                    if (
                        check_user_permission(
                            path=file_info["file_path"],
                            permissions=Permissions.WRITE,
                            user=session.get("user", ""),
                        )
                        is True
                    ):
                        os.rmdir(file_info["file_path"])
                        if (
                            CACHE_FOLDER_CONTENT_PREFIX
                            + "/".join(file_info["file_path"].split("/")[:-1])
                            in cache.keys()
                        ):
                            del cache[
                                CACHE_FOLDER_CONTENT_PREFIX
                                + "/".join(file_info["file_path"].split("/")[:-1])
                            ]
                            logger.info(
                                "Removing from cache: "
                                + CACHE_FOLDER_CONTENT_PREFIX
                                + file_info["file_path"]
                            )

                        flash(_("Folder removed."), "success")
                    else:
                        flash(_(
                            "You do not have the permission to delete this folder. If you recently changed the permissions, please allow up to 10 minutes for sync."),
                            "error",
                        )
                else:
                    flash(_(
                        f"The folder {file_info['file_path']} is not empty and cannot be removed."),
                        "error",
                    )
            else:
                pass

            return redirect(
                "/file_explorer?path=" + "/".join(file_info["file_path"].split("/")[:-1])
            )

        except Exception as err:
            logger.error(err)
            flash(_("Unable to download file. Did you remove it?"), "error")
            return redirect("/file_explorer")

    else:
        flash(_("Unable to delete ") + file_information["message"], "error")
        return redirect("/file_explorer")


@file_explorer.route("/file_explorer/flush_cache", methods=["POST"])
@login_required
@feature_flag(flag_name="FILE_BROWSER", mode="view")
def flush_cache():
    path = request.form["path"]
    if not path:
        return redirect("/file_explorer")
    else:
        if (
            check_user_permission(
                path=path, permissions=Permissions.READ, user=session.get("user", "")
            )
            is True
        ):
            if CACHE_FOLDER_CONTENT_PREFIX + path in cache.keys():
                del cache[CACHE_FOLDER_CONTENT_PREFIX + path]
                flash(_("Cache updated with the latest revision of the folder"), "success")
            else:
                flash(_("This location is not cached"), "error")
    return redirect("/file_explorer?path=" + path)


@file_explorer.route("/editor", methods=["GET"])
@login_required
@feature_flag(flag_name="FILE_BROWSER", mode="view")
def editor():
    uid = request.args.get("uid", "")
    if not uid:
        return redirect("/file_explorer")

    file_information = decrypt(uid)
    if file_information["success"] is True:
        file_info = json.loads(file_information["message"])
        if (
            check_user_permission(
                path=file_info["file_path"],
                permissions=Permissions.WRITE,
                user=session.get("user", ""),
            )
            is False
        ):
            flash(_("You are not authorized to download this file or this file is no longer available on the filesystem"))
            return redirect("/file_explorer")

        _resp = SocaHttpClient(
            endpoint="/api/system/files",
            headers={
                "X-EDH-USER": session["user"],
                "X-EDH-TOKEN": session["api_key"],
            },
        ).get(params={"file": file_info["file_path"]})
        if not _resp.get("success"):
            # i18n: message is a dynamic API response — translate at the API layer
            flash(_resp.get("message"))
            return redirect(
                "/file_explorer?path=" + "/".join(file_info["file_path"].split("/")[:-1])
            )
        else:
            file_data = _resp.get("message")

        known_extensions = {
            "c": "c",
            "cpp": "cpp",
            "csv": "csv",
            "html": "html",
            "java": "java",
            "js": "javascript",
            "json": "json",
            "md": "markdown",
            "php": "php",
            "pl": "perl",
            "ps": "powershell",
            "py": "python",
            "rb": "ruby",
            "scala": "scala",
            "sh": "shell",
            "bash": "bash",
            "ts": "typescript",
            "sql": "sql",
            "yaml": "yaml",
            "yml": "yaml",
        }

        if file_info["file_path"].split(".")[-1] in known_extensions.keys():
            file_syntax = known_extensions[file_info["file_path"].split(".")[-1]]
        else:
            file_syntax = "text"

        # get size of file
        return render_template(
            "editor.html",
            page="editor",
            file_to_edit=file_info["file_path"],
            file_data=file_data.split("\n"),
            file_syntax=file_syntax,
            api_key=session["api_key"],
        )
    else:
        flash(_(
            "Unable to access the file. Please try again:  ") + str(file_information),
            "error",
        )
        return redirect("/file_explorer")
