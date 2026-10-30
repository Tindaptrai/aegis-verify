"""Narrow Linux adapter for the optional root operator transaction.

All host commands are fixed argv, have bounded output/time and omit diagnostics
at the public boundary. No Manager, account, source or scenario operations exist.
"""
from contextlib import contextmanager, ExitStack
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import ssl
import stat
import subprocess
import threading
import secrets
import io
import zipfile
import shlex
import ctypes
import errno

from .contracts import (SetupError, load_profile, patch_http_config,
                        read_vendor_ca_archive, _yaml_value)
from .certificates import create_http_certificate
from .firewall import TABLE, PROFILE, ENTRYPOINT, firewall_create_text, verify_table, guard_unit, indexer_dropin
from .transaction import STATE_ROOT, atomic_write, encoded, fsync_directory
from .ufw_host import (UfwHostReader, LOADERS, LOADER_KEYS, DEPENDENCIES, RECORD_PATH,
                       strict_loaders, qualify_host, read_record, validate_record,
                       compatibility_record, same_record, decode_nft_json)

INSTALL_ROOT = Path(ENTRYPOINT).parent
PROFILE_ROOT = Path(PROFILE).parent
HTTP_ROOT = Path("/etc/wazuh-indexer/aegis-http")
GUARD_UNIT = Path("/etc/systemd/system/aegis-wazuh-http-guard.service")
DROPIN = Path("/etc/systemd/system/wazuh-indexer.service.d/90-aegis-http.conf")
MANIFEST = "KIT-MANIFEST.json"
KIT_FILES = ("Setup-Wazuh-HTTPS.py", *("https_setup/" + name + ".py" for name in
             ("__init__", "contracts", "certificates", "firewall", "host", "transaction", "cli", "ufw", "ufw_host")))
COMMANDS = {"systemctl": "/usr/bin/systemctl", "nft": "/usr/sbin/nft",
            "ss": "/usr/bin/ss", "ip": "/usr/sbin/ip", "dpkg-query": "/usr/bin/dpkg-query",
            "systemd-analyze": "/usr/bin/systemd-analyze", "openssl": "/usr/bin/openssl",
            "busctl": "/usr/bin/busctl"}
UNIT_EMPTY = ("RootDirectory", "RootImage", "ExecStartPre", "DropInPaths", "ReadOnlyPaths",
              "InaccessiblePaths", "BindPaths", "BindReadOnlyPaths", "RestrictAddressFamilies",
              "SystemCallFilter", "IPAddressDeny", "NetworkNamespacePath")
UNIT_NO = ("PrivateNetwork", "NoNewPrivileges", "ProtectHome", "ProtectSystem", "DynamicUser", "PrivateUsers")
UNIT_PROPERTIES = (*UNIT_EMPTY, *UNIT_NO, "User", "Group", "LoadState", "ActiveState",
                   "FragmentPath", "CapabilityBoundingSet")


def sha(body):
    return hashlib.sha256(body).hexdigest()


def validate_metadata(info, *, owners=frozenset({0}), directory=False, private=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid not in owners or info.st_mode & 0o022:
        raise SetupError("path_untrusted")
    if not directory and info.st_nlink != 1:
        raise SetupError("path_untrusted")
    if private and stat.S_IMODE(info.st_mode) != 0o600:
        raise SetupError("path_untrusted")


def identity(info):
    return {key: getattr(info, "st_" + key) for key in
            ("dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")}


def validate_vendor_metadata(info, *, uid, gid, directory=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(info.st_mode) or info.st_uid not in {0, uid} or info.st_gid not in {0, gid}
            or info.st_mode & 0o002 or info.st_mode & 0o020 and info.st_gid != gid
            or not directory and info.st_nlink != 1):
        raise SetupError("path_untrusted")


def publication_identity(info):
    """Rename changes ctime; all other frozen inode/content facts still apply."""
    return {key: value for key, value in identity(info).items() if key != "ctime_ns"}


class VendorPublisher:
    """Publication algorithm over held fds; staging parent is root-controlled.

    EXCHANGE preserves the actual displaced inode. This is deliberately not
    described as compare-and-swap: a writer inside the syscall window causes
    recovery-required, with displaced evidence retained and no service restart.
    """
    def __init__(self, ops, *, stage_fd):
        self.ops, self.stage = ops, stage_fd

    def _same(self, parent, name, fd, frozen, *, body=None, renamed=False):
        current = self.ops.stat(parent, name)
        held = self.ops.fstat(fd)
        compare = publication_identity if renamed else identity
        if current is None or compare(current) != compare(frozen) or compare(held) != compare(frozen):
            raise SetupError("vendor_drift")
        if body is not None:
            if self.ops.read(fd) != body or compare(self.ops.fstat(fd)) != compare(frozen):
                raise SetupError("vendor_drift")
            current = self.ops.stat(parent, name)
            if current is None or compare(current) != compare(frozen):
                raise SetupError("vendor_drift")

    def directory(self, parent, name, *, gid):
        if self.ops.stat(parent, name) is not None:
            raise SetupError("vendor_drift")
        # The only mkdir/open/metadata sequence is under the protected staging
        # fd. No chmod/chown is ever issued against a vendor-directory name.
        self.ops.mkdir(self.stage, "new")
        fd = self.ops.open(self.stage, "new", directory=True)
        try:
            self.ops.metadata(fd, 0, gid, 0o750)
            frozen = self.ops.fstat(fd)
            self._same(self.stage, "new", fd, frozen)
            self.ops.sync(fd)
            self.ops.rename(self.stage, "new", parent, name)
            self.ops.sync(self.stage)
            self.ops.sync(parent)
            self._same(parent, name, fd, frozen, renamed=True)
        finally:
            self.ops.close(fd)

    def file(self, parent, name, body, *, uid, gid, mode, owner, group, expected):
        before = self.ops.stat(parent, name)
        target_fd = new_fd = displaced_fd = None
        try:
            original = None
            if before is not None:
                validate_vendor_metadata(before, uid=uid, gid=gid)
                if expected is None:
                    raise SetupError("vendor_drift")
                target_fd = self.ops.open(parent, name)
                self._same(parent, name, target_fd, before)
                # Existing vendor replacements preserve the caller's frozen
                # attributes; a later inspection must not bless an intervening
                # ownership/mode edit as a new baseline (including rollback).
                held = self.ops.fstat(target_fd)
                if (held.st_uid, held.st_gid, stat.S_IMODE(held.st_mode)) != (owner, group, mode):
                    raise SetupError("vendor_drift")
                original = self.ops.read(target_fd)
                self._same(parent, name, target_fd, before, body=original)
                if sha(original) not in expected:
                    raise SetupError("vendor_drift")
            elif expected is not None:
                raise SetupError("vendor_drift")
            new_fd = self.ops.open(self.stage, "new", create=True)
            # Construct privately as root0600; desired service metadata is set
            # only after writing, while the containing directory is still0700.
            self.ops.write(new_fd, body)
            self.ops.metadata(new_fd, owner, group, mode)
            self.ops.sync(new_fd)
            prepared = self.ops.fstat(new_fd)
            if (not stat.S_ISREG(prepared.st_mode) or prepared.st_nlink != 1 or
                    (prepared.st_uid, prepared.st_gid, stat.S_IMODE(prepared.st_mode)) != (owner, group, mode)):
                raise SetupError("vendor_drift")
            self._same(self.stage, "new", new_fd, prepared, body=body)
            if before is not None:
                self._same(parent, name, target_fd, before, body=original)
            elif self.ops.stat(parent, name) is not None:
                raise SetupError("vendor_drift")
            self.ops.rename(self.stage, "new", parent, name, exchange=before is not None)
            self.ops.sync(self.stage)
            self.ops.sync(parent)
            if before is not None:
                # Keep the displaced entry even on failure; it may be somebody
                # else's intervening edit, and must never be unlinked/overwritten.
                displaced = self.ops.stat(self.stage, "new")
                if displaced is None or not stat.S_ISREG(displaced.st_mode):
                    raise SetupError("vendor_drift")
                displaced_fd = self.ops.open(self.stage, "new")
                self.ops.preserve("displaced", displaced_fd)
                self._same(self.stage, "new", displaced_fd, before, body=original, renamed=True)
            self._same(parent, name, new_fd, prepared, body=body, renamed=True)
        finally:
            for fd in (displaced_fd, new_fd, target_fd):
                if fd is not None:
                    self.ops.close(fd)


class PublicationOps:
    """Linux syscall adapter, used only inside a root-owned staging directory."""
    def __init__(self, stage_fd):
        self.stage = stage_fd
        try:
            self.renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
        except (AttributeError, OSError):
            raise SetupError("filesystem_unsupported") from None
        self.renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        self.renameat2.restype = ctypes.c_int

    def stat(self, parent, name):
        try:
            return os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def open(self, parent, name, *, create=False, directory=False):
        flags = os.O_NOFOLLOW | (os.O_RDWR | os.O_CREAT | os.O_EXCL if create else os.O_RDONLY | os.O_NONBLOCK)
        if directory:
            flags |= os.O_DIRECTORY
        return os.open(name, flags, 0o600, dir_fd=parent)

    def mkdir(self, parent, name):
        os.mkdir(name, 0o700, dir_fd=parent)

    def fstat(self, fd):
        return os.fstat(fd)

    def read(self, fd):
        os.lseek(fd, 0, os.SEEK_SET)
        body = bytearray()
        while len(body) <= 1024 * 1024:
            chunk = os.read(fd, min(65536, 1024 * 1024 + 1 - len(body)))
            if not chunk:
                return bytes(body)
            body.extend(chunk)
        raise SetupError("vendor_drift")

    def write(self, fd, body):
        offset = 0
        while offset < len(body):
            written = os.write(fd, body[offset:])
            if not written:
                raise SetupError("vendor_drift")
            offset += written

    def metadata(self, fd, uid, gid, mode):
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)

    def sync(self, fd):
        os.fsync(fd)

    def close(self, fd):
        os.close(fd)

    def rename(self, src_parent, src, dst_parent, dst, *, exchange=False):
        # Linux UAPI: RENAME_NOREPLACE=1, RENAME_EXCHANGE=2. No fallback.
        rc = self.renameat2(src_parent, os.fsencode(src), dst_parent, os.fsencode(dst), 2 if exchange else 1)
        if rc != 0:
            code = ctypes.get_errno()
            if code in {errno.EXDEV, errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
                raise SetupError("filesystem_unsupported")
            raise SetupError("vendor_drift")

    def preserve(self, name, fd):
        # Original inode stays under the root-only staging ancestor. A separate
        # root0600 snapshot preserves observed bytes even if an old writer still
        # has an fd to the displaced service-owned inode.
        body = self.read(fd)
        saved = self.open(self.stage, name + ".snapshot", create=True)
        try:
            self.metadata(saved, 0, 0, 0o600)
            self.write(saved, body)
            self.sync(saved)
            self.sync(self.stage)
        finally:
            self.close(saved)

    def qualify(self):
        """Probe both required flags in the private staging directory first."""
        for name in ("probe-a", "probe-b"):
            fd = self.open(self.stage, name, create=True)
            self.close(fd)
        self.rename(self.stage, "probe-a", self.stage, "probe-c")
        self.rename(self.stage, "probe-c", self.stage, "probe-b", exchange=True)
        os.unlink("probe-b", dir_fd=self.stage)
        os.unlink("probe-c", dir_fd=self.stage)
        self.sync(self.stage)


def verify_listeners(text, p, *, expanded):
    found = {9200: [], 9300: []}
    try:
        for line in text.splitlines():
            fields = line.split()
            if len(fields) < 5:
                raise ValueError
            address, port = fields[3].rsplit(":", 1)
            if port not in {"9200", "9300"}:
                continue
            address = address.strip("[]")
            ip = ipaddress.ip_address(address)
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
                ip = ip.ipv4_mapped
            found[int(port)].append(str(ip))
        expected = ["127.0.0.1", p.indexer_ip] if expanded else ["127.0.0.1"]
        if sorted(found[9200]) != sorted(expected) or found[9300] != ["127.0.0.1"]:
            raise ValueError
    except (ValueError, IndexError):
        raise SetupError("listeners_unsupported") from None


def stable_firewall(document):
    """Keep all expressions, counter presence and policy-bearing attributes.

    Only object handles, metainfo, and counter byte/packet values are volatile.
    Stateful dynamic rules are deliberately unsupported: their expiry/state
    cannot be frozen safely by this kit.
    """
    def clean(value):
        if isinstance(value, list):
            return [clean(v) for v in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if key in {"expires", "quota", "limit", "synproxy", "flowtable"}:
                    raise SetupError("host_unsupported")
                if key == "counter" and isinstance(item, dict):
                    result[key] = {k: clean(v) for k, v in item.items() if k not in {"bytes", "packets"}}
                else:
                    result[key] = clean(item)
            return result
        return value
    if type(document) is not dict or set(document) != {"nftables"} or type(document["nftables"]) is not list:
        raise SetupError("firewall_mismatch")
    result = []
    for obj in document["nftables"]:
        if type(obj) is not dict or len(obj) != 1:
            raise SetupError("firewall_mismatch")
        kind, body = next(iter(obj.items()))
        if kind == "metainfo":
            continue
        if type(body) is not dict:
            raise SetupError("firewall_mismatch")
        ignored = {"handle", "bytes", "packets"} if kind == "counter" else {"handle"}
        result.append({kind: clean({k: v for k, v in body.items() if k not in ignored})})
    return {"nftables": result}


def validate_unit(props):
    if (any(props.get(k) != "" for k in UNIT_EMPTY) or
            any(props.get(k) != "no" for k in UNIT_NO) or
            props.get("User") != "wazuh-indexer" or props.get("Group") != "wazuh-indexer" or
            props.get("LoadState") != "loaded" or props.get("ActiveState") != "active" or
            props.get("FragmentPath") not in {"/usr/lib/systemd/system/wazuh-indexer.service",
                                               "/lib/systemd/system/wazuh-indexer.service"}):
        raise SetupError("host_unsupported")
    caps = props.get("CapabilityBoundingSet", "").lower().split()
    if not {"cap_net_admin", "cap_dac_override"}.issubset(caps):
        raise SetupError("host_unsupported")


def validate_identity(p, hostname, wazuh_version, search_version, addresses):
    if (hostname != p.hostname or not re.fullmatch(r"4\.14\.4(?:-\d+)?", wazuh_version) or
            search_version != "2.19.4" or p.indexer_ip not in addresses):
        raise SetupError("host_unsupported")


class SecureFS:
    """Stock vendor files may be vendor-owned; privileged ancestors must be root-owned."""
    def resolve(self, path):
        return Path(path).resolve(strict=True)

    def trusted(self, path, *, owners=frozenset({0}), private=False, missing=False):
        path = Path(path)
        if not path.is_absolute() or ".." in path.parts:
            raise SetupError("path_untrusted")
        for parent in reversed(path.parents):
            validate_metadata(parent.lstat(), directory=True)
        try:
            info = path.lstat()
        except FileNotFoundError:
            if missing:
                return None
            raise SetupError("path_untrusted") from None
        validate_metadata(info, owners=owners, private=private, directory=stat.S_ISDIR(info.st_mode))
        return info

    def read(self, path, *, owners=frozenset({0}), private=False, limit=1024 * 1024):
        before = self.trusted(path, owners=owners, private=private)
        validate_metadata(before, owners=owners, private=private)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb", buffering=0) as stream:
            if identity(before) != identity(os.fstat(stream.fileno())):
                raise SetupError("state_changed")
            body = stream.read(limit + 1)
            if len(body) > limit or identity(before) != identity(os.fstat(stream.fileno())):
                raise SetupError("state_changed")
        return body

    def read_indexer_jar(self, uid, gid):
        """Read only the fixed compatibility artifact; never execute vendor code.

        Service ownership is allowed only below /usr/share. Held descriptors and
        named entries are rechecked, but these observations are not an atomic
        snapshot or a vendor-signature attestation.
        """
        names = ("/", "usr", "share", "wazuh-indexer", "lib", "opensearch-2.19.4.jar")
        limit = 32 * 1024 * 1024
        held = []
        with ExitStack() as descriptors:
            for index, name in enumerate(names):
                directory = index < len(names) - 1
                flags = os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if directory else os.O_NONBLOCK)
                fd = os.open(name, flags, **({"dir_fd": held[-1][0]} if held else {}))
                # Register immediately so metadata/validation failures also close it.
                descriptors.callback(os.close, fd)
                held.append((fd, None))
                info = os.fstat(fd)
                held[-1] = (fd, identity(info))
                validate_metadata(info, owners={0, uid} if index >= 3 else {0}, directory=directory)
                if index >= 3 and info.st_gid not in {0, gid}:
                    raise SetupError("path_untrusted")
                if not directory and not 0 < info.st_size <= limit:
                    raise SetupError("path_untrusted")
            body = bytearray()
            while len(body) <= limit:
                chunk = os.read(held[-1][0], min(65536, limit + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
            if len(body) > limit or len(body) != held[-1][1]["size"]:
                raise SetupError("state_changed")
            for index, (fd, frozen) in enumerate(held):
                parent = held[max(0, index - 1)][0]
                named = os.stat(names[index], dir_fd=parent, follow_symlinks=False)
                if identity(os.fstat(fd)) != frozen or identity(named) != frozen:
                    raise SetupError("state_changed")
            return bytes(body)

    def archive_stat(self, path):
        # Writable home ancestors are allowed, links are not. Only the root-owned
        # regular archive inode is trusted, and is pinned again after opening.
        path = Path(path)
        for parent in (path, *path.parents):
            if stat.S_ISLNK(parent.lstat().st_mode):
                raise SetupError("path_untrusted")
        info = path.lstat()
        validate_metadata(info, private=True)
        if not 0 < info.st_size <= 32 * 1024 * 1024:
            raise SetupError("archive_invalid")
        return identity(info)

    @contextmanager
    def archive(self, path, frozen):
        if self.archive_stat(path) != frozen:
            raise SetupError("state_changed")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb", buffering=0) as stream:
            if identity(os.fstat(stream.fileno())) != frozen or self.archive_stat(path) != frozen:
                raise SetupError("state_changed")
            yield stream
            if identity(os.fstat(stream.fileno())) != frozen or self.archive_stat(path) != frozen:
                raise SetupError("state_changed")

    def mkdir(self, path, *, mode=0o700, gid=0):
        path = Path(path)
        if path.exists():
            info = self.trusted(path)
            if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != mode or info.st_gid != gid:
                raise SetupError("path_untrusted")
            return
        self.trusted(path.parent)
        path.mkdir(mode=mode)
        os.chown(path, 0, gid)
        os.chmod(path, mode)
        fsync_directory(path.parent)

    def write(self, path, body, *, mode=0o600, uid=0, gid=0):
        self.trusted(Path(path).parent)
        self.trusted(path, owners={0, uid}, missing=True)
        atomic_write(path, body, mode=mode, uid=uid, gid=gid)

    def unlink(self, path):
        if Path(path).exists():
            self.trusted(path)
            Path(path).unlink()
            fsync_directory(Path(path).parent)

    @contextmanager
    def vendor_parent(self, path, uid, gid):
        """Pin each directory; never traverse a service-controlled symlink.

        Path names are revalidated against held fds after the operation. A rename
        cannot redirect a privileged write outside the opened vendor directory.
        """
        path = PurePosixPath(path)
        if not path.is_absolute() or not path.is_relative_to("/etc/wazuh-indexer") or ".." in path.parts:
            raise SetupError("path_untrusted")
        descriptors = []
        links = []
        def directory_id(info):
            return tuple(getattr(info, "st_" + key) for key in ("dev", "ino", "uid", "gid", "mode"))
        try:
            root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            descriptors.append(root)
            validate_metadata(os.fstat(root), directory=True)
            parent_fd = root
            for position, name in enumerate(path.parts[1:-1]):
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                descriptors.append(fd)
                info = os.fstat(fd)
                if position == 0:
                    validate_metadata(info, directory=True)
                else:
                    validate_vendor_metadata(info, uid=uid, gid=gid, directory=True)
                links.append((parent_fd, name, directory_id(info), fd))
                parent_fd = fd
            yield parent_fd, path.name
            for previous, name, frozen, fd in links:
                if (directory_id(os.fstat(fd)) != frozen or
                        directory_id(os.stat(name, dir_fd=previous, follow_symlinks=False)) != frozen):
                    raise SetupError("state_changed")
        finally:
            for fd in reversed(descriptors):
                os.close(fd)

    def vendor_stat(self, path, uid, gid):
        with self.vendor_parent(path, uid, gid) as (parent, name):
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            validate_vendor_metadata(info, uid=uid, gid=gid, directory=stat.S_ISDIR(info.st_mode))
            return info

    def vendor_read(self, path, uid, gid):
        with self.vendor_parent(path, uid, gid) as (parent, name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            with os.fdopen(fd, "rb", buffering=0) as stream:
                before = os.fstat(fd)
                validate_vendor_metadata(before, uid=uid, gid=gid)
                raw = stream.read(1024 * 1024 + 1)
                if (len(raw) > 1024 * 1024 or identity(before) != identity(os.fstat(fd)) or
                        identity(before) != identity(os.stat(name, dir_fd=parent, follow_symlinks=False))):
                    raise SetupError("state_changed")
        return raw

    def vendor_mkdir(self, path, uid, gid):
        try:
            with self.publication(path, "directory") as publisher:
                with self.vendor_parent(path, uid, gid) as (parent, name):
                    if os.fstat(parent).st_dev != publisher.ops.fstat(publisher.stage).st_dev:
                        raise SetupError("filesystem_unsupported")
                    publisher.directory(parent, name, gid=gid)
        except (OSError, SetupError) as exc:
            if isinstance(exc, SetupError) and exc.code == "filesystem_unsupported":
                raise
            raise SetupError("vendor_drift") from None

    def vendor_write(self, path, body, uid, gid, *, mode=0o640, owner=0, group=None, expected=None):
        try:
            with self.publication(path, "file") as publisher:
                with self.vendor_parent(path, uid, gid) as (parent, name):
                    if os.fstat(parent).st_dev != publisher.ops.fstat(publisher.stage).st_dev:
                        raise SetupError("filesystem_unsupported")
                    publisher.file(parent, name, body, uid=uid, gid=gid, mode=mode, owner=owner,
                                   group=gid if group is None else group, expected=expected)
        except (OSError, SetupError) as exc:
            if isinstance(exc, SetupError) and exc.code == "filesystem_unsupported":
                raise
            raise SetupError("vendor_drift") from None

    @contextmanager
    def publication(self, path, kind):
        """Protected provenance comes from the entire root-owned ancestor chain.

        Staging never lives below the service-owned config tree. All operations,
        including successful exchanges, retain their evidence for human review.
        Prepared/failed records block automatic recovery after an interruption.
        """
        root_info = self.trusted(PROFILE_ROOT)
        if stat.S_IMODE(root_info.st_mode) != 0o700:
            raise SetupError("path_untrusted")
        root_fd = os.open(PROFILE_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stage_fd = None
        try:
            if identity(os.fstat(root_fd)) != identity(root_info):
                raise SetupError("vendor_drift")
            stage_name = "publication-" + secrets.token_hex(16)
            # Only root can change this parent. This is not a vendor mkdir/open
            # provenance guess based on owner or ctime of an untrusted entry.
            os.mkdir(stage_name, 0o700, dir_fd=root_fd)
            stage_fd = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
            os.fchown(stage_fd, 0, 0)
            os.fchmod(stage_fd, 0o700)
            os.fsync(root_fd)
            record_path = PROFILE_ROOT / stage_name / "publication.json"
            record = {"schema_version": 1, "kind": kind, "target": str(path), "status": "prepared"}
            self.write(record_path, encoded(record))
            try:
                ops = PublicationOps(stage_fd)
                ops.qualify()
                yield VendorPublisher(ops, stage_fd=stage_fd)
                # Recheck the protected root and opened stage name before marking
                # completion, after the vendor-parent context has also validated.
                for held, current in ((os.fstat(root_fd), PROFILE_ROOT.lstat()),
                                      (os.fstat(stage_fd), os.stat(stage_name, dir_fd=root_fd, follow_symlinks=False))):
                    if any(getattr(held, "st_" + key) != getattr(current, "st_" + key)
                           for key in ("dev", "ino", "uid", "gid", "mode")):
                        raise SetupError("vendor_drift")
                record["status"] = "complete"
                self.write(record_path, encoded(record))
            except BaseException:
                record["status"] = "failed"
                self.write(record_path, encoded(record))
                raise
        finally:
            if stage_fd is not None:
                os.close(stage_fd)
            os.close(root_fd)

    def check_publications(self):
        if not PROFILE_ROOT.exists():
            return
        self.trusted(PROFILE_ROOT)
        for directory in PROFILE_ROOT.glob("publication-*"):
            self.trusted(directory)
            try:
                record = json.loads(self.read(directory / "publication.json", private=True))
                if record.get("status") != "complete":
                    raise ValueError
            except (OSError, ValueError, SetupError):
                raise SetupError("vendor_drift") from None


class Commands:
    def __init__(self, fs):
        self.fs = fs

    def run(self, name, *args, data=None):
        # Resolve distro executable aliases, then validate root-only provenance.
        executable = Path(COMMANDS[name]).resolve(strict=True)
        self.fs.trusted(executable)
        return self._execute(str(executable), args, data=data)

    def run_selected(self, name, *args):
        # Called only after the UFW adapter's held-file and fixed-alias gates.
        # xtables-multi dispatches on argv[0]; resolving its name loses that.
        allowed = {"iptables": ("--version",), "ip6tables": ("--version",)}
        if allowed.get(name) != args:
            raise SetupError("ufw_unsupported")
        executable = "/usr/sbin/xtables-nft-multi"
        self.fs.trusted(executable)
        return self._execute(executable, args, argv0="/usr/sbin/" + name)

    def _execute(self, executable, args, *, data=None, argv0=None):
        output = [bytearray(), bytearray()]
        overflow = []
        proc = subprocess.Popen([argv0 or str(executable), *args], executable=str(executable),
                                stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        def drain(pipe, target):
            while chunk := pipe.read(8192):
                if len(target) + len(chunk) > 4 * 1024 * 1024:
                    overflow.append(True)
                    proc.kill()
                    break
                target.extend(chunk)
            pipe.close()
        threads = [threading.Thread(target=drain, args=(pipe, target), daemon=True)
                   for pipe, target in zip((proc.stdout, proc.stderr), output)]
        for thread in threads:
            thread.start()
        try:
            if data is not None:
                proc.stdin.write(data)
                proc.stdin.close()
            proc.wait(timeout=45)
        except (OSError, subprocess.TimeoutExpired):
            proc.kill()
            proc.wait(timeout=5)
            raise SetupError("command_failed") from None
        finally:
            for thread in threads:
                thread.join(timeout=5)
        if proc.returncode or overflow or any(t.is_alive() for t in threads):
            raise SetupError("command_failed")
        return bytes(output[0]), bytes(output[1])


class LinuxHost:
    def __init__(self, *, fs=None, commands=None, bundle=None):
        self.fs = fs if fs is not None else SecureFS()
        self.commands = commands if commands is not None else Commands(self.fs)
        self.bundle = Path(bundle) if bundle is not None else Path(__file__).resolve().parent.parent

    @staticmethod
    def require_root():
        if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
            raise SetupError("root_required")

    def run(self, name, *args, data=None):
        return self.commands.run(name, *args, data=data)[0]

    def vread(self, path):
        return self.fs.vendor_read(path, self.uid, self.gid)

    def vstat(self, path):
        return self.fs.vendor_stat(path, self.uid, self.gid)

    def service_identity(self):
        import pwd
        import grp
        account = pwd.getpwnam("wazuh-indexer")
        group = grp.getgrgid(account.pw_gid)
        if (account.pw_uid == 0 or account.pw_gid == 0 or group.gr_name != "wazuh-indexer" or
                set(group.gr_mem) - {account.pw_name} or
                any(user.pw_gid == account.pw_gid and user.pw_uid != account.pw_uid for user in pwd.getpwall())):
            raise SetupError("host_unsupported")
        self.uid, self.gid = account.pw_uid, account.pw_gid

    def properties(self, unit, keys):
        if (type(unit) is not str or len(unit) > 255 or
                not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]*\.service", unit)):
            raise SetupError("host_unsupported")
        # Match systemd's bus_label_escape, not filesystem/unit-name escaping.
        label = "".join(char if char.isalpha() or index > 0 and char.isdigit()
                        else "_%02x" % ord(char) for index, char in enumerate(unit))
        def service_property(key):
            return self.run("busctl", "--system", "get-property", "org.freedesktop.systemd1",
                            "/org/freedesktop/systemd1/unit/" + label,
                            "org.freedesktop.systemd1.Service", key)
        text = self.run("systemctl", "show", unit, "--no-pager", "--property=" + ",".join(keys)).decode()
        props = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
        if set(props) == set(keys) - {"ExecStartPre"} and "ExecStartPre" in keys:
            response = service_property("ExecStartPre")
            if response not in (b"a(sasbttttuii) 0", b"a(sasbttttuii) 0\n"):
                raise SetupError("host_unsupported")
            props["ExecStartPre"] = ""
        if set(props) != set(keys):
            raise SetupError("host_unsupported")
        for key in ("RestrictAddressFamilies", "SystemCallFilter"):
            if key in props and props[key] in ("", "~"):
                # systemctl renders an empty deny-list as '~'. Empty display
                # also needs typed denial-mode confirmation: true/0 restricts.
                if service_property(key) not in (b"(bas) false 0", b"(bas) false 0\n"):
                    raise SetupError("host_unsupported")
                props[key] = ""
        return props

    def firewall(self):
        return decode_nft_json(self.run("nft", "--json", "list", "ruleset"))

    def ufw_reader(self):
        return UfwHostReader(self)

    def dependency_properties(self, unit):
        # Unit names are selected from the bounded effective dependency graph.
        if not re.fullmatch(r"[A-Za-z0-9_.@\\:-]+\.[a-z]+", unit) or len(unit) > 255:
            raise SetupError("ufw_unsupported")
        raw = self.run("systemctl", "show", "--all", "--no-pager",
                       "--property=" + ",".join(DEPENDENCIES), "--", unit)
        try:
            if len(raw) > 65536:
                raise ValueError
            text = raw.decode("ascii")
            if not re.fullmatch(r"[\x20-\x7e\n]*", text):
                raise ValueError
            pairs = [line.split("=", 1) for line in text.splitlines()]
            props = dict(pairs)
            if len(pairs) != len(props) or set(props) != set(DEPENDENCIES):
                raise ValueError
            for key, value in props.items():
                names = shlex.split(value, comments=False, posix=True)
                if (len(names) > 512 or len(names) != len(set(names)) or
                        any(len(name) > 255 or not re.fullmatch(r"[A-Za-z0-9_.@\\:-]+\.[a-z]+", name) for name in names)):
                    raise ValueError
                # v255 shell_maybe_quote(str, 0): only backslash in the allowed
                # unit alphabet needs quoting. Decode presentation, not \xNN IDs.
                rendered = " ".join('"' + name.replace("\\", "\\\\") + '"' if "\\" in name else name for name in names)
                if rendered != value:
                    raise ValueError
                props[key] = " ".join(names)
            return props
        except (ValueError, UnicodeError):
            raise SetupError("ufw_unsupported") from None

    def firewall_loaders(self):
        return {name: self.properties(name, LOADER_KEYS) for name in LOADERS}

    def guard_unit_present(self):
        present = self.fs.trusted(GUARD_UNIT, missing=True) is not None
        props = self.properties("aegis-wazuh-http-guard.service",
                                ("LoadState", "FragmentPath", "Transient", "DropInPaths", "NeedDaemonReload"))
        expected = {"LoadState": "loaded" if present else "not-found",
                    "FragmentPath": str(GUARD_UNIT) if present else "", "Transient": "no",
                    "DropInPaths": "", "NeedDaemonReload": "no"}
        if props != expected or present and self.fs.read(GUARD_UNIT) != guard_unit().encode():
            raise SetupError("ufw_unsupported")
        return present

    def foreign_firewall(self, observation=None):
        rules = stable_firewall(self.firewall() if observation is None else observation)
        own = self.table(rules)
        return {"nftables": [obj for obj in rules["nftables"] if obj not in own["nftables"]]}

    def admit_firewall_loaders(self, loaders=None, firewall=None):
        """Ambient read-only qualification; never grants startup record authority."""
        loaders = self.firewall_loaders() if loaders is None else loaders
        if strict_loaders(loaders):
            return None
        return qualify_host(self, loaders, firewall)

    def read_firewall_compatibility(self):
        return read_record(self)

    def verify_installed_firewall_compatibility(self, profile):
        record = self.read_firewall_compatibility()
        loaders = self.firewall_loaders()
        if record is None:
            if not strict_loaders(loaders):
                raise SetupError("ufw_drift")
            return
        validate_record(record, profile)
        current = qualify_host(self, loaders)
        if not same_record(record, compatibility_record(profile, current)):
            raise SetupError("ufw_drift")

    def install_firewall_compatibility(self, profile, fingerprint):
        if self.read_firewall_compatibility() is not None:
            raise SetupError("ufw_drift")
        if not same_record(fingerprint, self.admit_firewall_loaders()):
            raise SetupError("state_changed")
        if fingerprint is not None:
            self.fs.write(Path(RECORD_PATH), encoded(compatibility_record(profile, fingerprint)))
        self.verify_installed_firewall_compatibility(profile)

    def revalidate_firewall_facts(self, facts):
        if (stable_firewall(self.firewall()) != facts["firewall"] or
                not same_record(self.admit_firewall_loaders(), facts["ufw_compatibility"])):
            raise SetupError("state_changed")

    def check_recovery_firewall_compatibility(self, p, snapshot, work):
        """Missing is safe only for an untouched or fully restored HTTP install."""
        if snapshot.get("ufw_compatibility_original", "unknown") is not None:
            raise SetupError("recovery_required")
        raw = self.fs.read(work / "ufw-compatibility.json", private=True, limit=8 * 1024 * 1024)
        if sha(raw) != snapshot.get("ufw_compatibility_sha256"):
            raise SetupError("recovery_required")
        expected = json.loads(raw)
        current = self.read_firewall_compatibility()
        if current is None and expected is not None:
            if (self.table(self.firewall())["nftables"] or GUARD_UNIT.exists() or DROPIN.exists() or
                    sha(self.vread(p.config_path)) != snapshot["original_sha256"]):
                raise SetupError("recovery_required")
            # Requalify ambient evidence, but never install a missing record here.
            actual = compatibility_record(p, self.admit_firewall_loaders())
            if not same_record(expected, actual):
                raise SetupError("ufw_drift")
        elif not same_record(current, expected):
            raise SetupError("ufw_drift")
        else:
            self.verify_installed_firewall_compatibility(p)
        return expected, current

    def restore_firewall_compatibility(self, p, snapshot, work):
        # Coordinator calls this only after old localhost TLS/listener verification
        # and owned-guard removal. Unknown records are retained for human recovery.
        _, current = self.check_recovery_firewall_compatibility(p, snapshot, work)
        if current is not None:
            self.fs.unlink(Path(RECORD_PATH))

    def table(self, ruleset):
        result = []
        for obj in ruleset["nftables"]:
            kind, body = next(iter(obj.items()))
            if kind != "metainfo" and body.get("family") == "inet" and (
                    body.get("table") == TABLE or kind == "table" and body.get("name") == TABLE):
                result.append(obj)
        return {"nftables": result}

    def bundle_files(self, *, required=True):
        manifest_path = self.bundle / MANIFEST
        if not manifest_path.exists() and not required:
            # A root-staged check remains available before native qualification.
            return {name: self.fs.read(self.bundle / name) for name in KIT_FILES}
        try:
            manifest = json.loads(self.fs.read(manifest_path, private=True))
            if (set(manifest) != {"schema_version", "source_commit", "native_proof", "files"} or
                    manifest["schema_version"] != 1 or not re.fullmatch("[0-9a-f]{40}", manifest["source_commit"]) or
                    not (manifest["native_proof"] is None or type(manifest["native_proof"]) is dict) or
                    set(manifest["files"]) != set(KIT_FILES)):
                raise ValueError
            files = {name: self.fs.read(self.bundle / name) for name in KIT_FILES}
            if any(sha(body) != manifest["files"][name] for name, body in files.items()):
                raise ValueError
            files[MANIFEST] = encoded(manifest)
            return files
        except (ValueError, KeyError, TypeError, FileNotFoundError):
            raise SetupError("manifest_invalid") from None

    def prepare_state(self):
        self.require_root()
        self.fs.trusted(STATE_ROOT, missing=True)

    def preflight(self, profile_path):
        self.require_root()
        raw = self.fs.read(profile_path, private=True, limit=16384)
        p = load_profile(raw)
        self.service_identity()
        owners = {0, self.uid}
        files = self.bundle_files(required=False)
        props = self.properties("wazuh-indexer.service", UNIT_PROPERTIES)
        validate_unit(props)
        unit_path = self.fs.resolve(props["FragmentPath"])
        unit = self.fs.read(unit_path)
        environment = self.startup_environment(unit, p)
        # Package metadata, never executing vendor Java or Manager processes.
        version = self.run("dpkg-query", "-W", "-f=${Version}", "wazuh-indexer").decode().strip()
        jar_bytes = self.fs.read_indexer_jar(self.uid, self.gid)
        try:
            with zipfile.ZipFile(io.BytesIO(jar_bytes)) as zipped:
                info = zipped.getinfo("META-INF/MANIFEST.MF")
                if info.file_size > 65536:
                    raise ValueError
                manifest = zipped.read(info).decode()
            versions = re.findall(r"^Implementation-Version: ([^\r\n]+)", manifest, re.MULTILINE)
            if versions != ["2.19.4"]:
                raise ValueError
        except (ValueError, KeyError, zipfile.BadZipFile):
            raise SetupError("host_unsupported") from None
        addresses = [a["local"] for entry in json.loads(self.run("ip", "-j", "-4", "address", "show"))
                     for a in entry.get("addr_info", []) if a.get("family") == "inet"]
        validate_identity(p, socket.gethostname(), version, "2.19.4", addresses)
        listeners = self.run("ss", "-H", "-ltn").decode()
        verify_listeners(listeners, p, expanded=False)
        loaders = self.firewall_loaders()
        config = self.vread(p.config_path)
        patch_http_config(config, p)
        retained = self.config_files(config, p, owners)
        ca = self.vread(p.ca_path)
        leaf = self.vread(p.leaf_path)
        if (sha(ca) != p.expected_ca_file_sha256 or
                sha(ssl.PEM_cert_to_DER_cert(ca.decode("ascii"))) != p.expected_ca_der_sha256 or
                sha(ssl.PEM_cert_to_DER_cert(leaf.decode("ascii"))) != p.expected_leaf_der_sha256):
            raise SetupError("certificate_invalid")
        archive = self.fs.archive_stat(p.ca_archive)
        # Check intentionally reads zero archive bytes (even gzip magic is optional).
        firewall = stable_firewall(self.firewall())
        if self.table(firewall)["nftables"]:
            raise SetupError("firewall_mismatch")
        compatibility = self.admit_firewall_loaders(loaders, firewall)
        if HTTP_ROOT.exists() or HTTP_ROOT.is_symlink():
            raise SetupError("intent_exists")
        for path in (PROFILE_ROOT, INSTALL_ROOT, GUARD_UNIT, DROPIN):
            # Parents that do not yet exist are checked up to the nearest existing
            # root-owned ancestor; a kit-owned path must not already be present.
            if path.exists() or path.is_symlink():
                raise SetupError("intent_exists")
            parent = path.parent
            while not parent.exists():
                parent = parent.parent
            self.fs.trusted(parent)
        self.fs.trusted(STATE_ROOT, missing=True)
        if (STATE_ROOT / "intent.json").exists():
            raise SetupError("intent_exists")
        return p, sha(raw), {"hostname": p.hostname, "wazuh_version": version, "opensearch_version": "2.19.4",
               "uid": self.uid, "gid": self.gid, "config": sha(config), "config_metadata": identity(self.vstat(p.config_path)),
               "opensearch_jar": sha(jar_bytes),
               "unit_path": str(unit_path), "unit": sha(unit), "unit_properties": props,
               "environment_files": environment,
               "loaders": loaders, "ufw_compatibility": compatibility,
               "retained": retained, "archive": archive, "firewall": firewall,
               "bundle": {name: sha(body) for name, body in files.items()}}

    def config_files(self, raw, p, owners):
        values = {}
        for line in raw.decode().splitlines():
            match = re.match(r"^([A-Za-z0-9_.]+):\s*(.*)$", line)
            if match:
                try:
                    values[match[1]] = _yaml_value(match[2])
                except ValueError:
                    continue  # Unsupported non-target lists were validated by patcher.
        if values.get("network.host") not in ("127.0.0.1", ["127.0.0.1"]) or values.get("plugins.security.ssl.http.enabled") != "true":
            raise SetupError("config_unsupported")
        for key in ("transport.host", "transport.bind_host", "transport.publish_host"):
            if key in values and values[key] not in ("127.0.0.1", ["127.0.0.1"]):
                raise SetupError("config_unsupported")
        retained = {}
        for section in ("http", "transport"):
            for kind in ("pemcert_filepath", "pemkey_filepath", "pemtrustedcas_filepath"):
                value = values.get(f"plugins.security.ssl.{section}.{kind}")
                if not isinstance(value, str):
                    raise SetupError("config_unsupported")
                path = PurePosixPath(value)
                if not path.is_absolute():
                    path = PurePosixPath("/etc/wazuh-indexer") / path
                if not path.is_relative_to("/etc/wazuh-indexer") or ".." in path.parts or str(path).startswith(str(HTTP_ROOT)):
                    raise SetupError("path_untrusted")
                if section == "http" and kind == "pemcert_filepath" and str(path) != p.leaf_path:
                    raise SetupError("config_unsupported")
                if kind == "pemtrustedcas_filepath" and str(path) != p.ca_path:
                    raise SetupError("config_unsupported")
                info = self.vstat(path)
                # Private stock keys are stat-only: no hashes or key reads in check.
                retained[str(path)] = {"metadata": identity(info), "private": kind == "pemkey_filepath"}
                if kind != "pemkey_filepath":
                    retained[str(path)]["sha256"] = sha(self.vread(path))
        return retained

    def startup_environment(self, unit, p):
        """Read selected config-directory settings privately; return only hashes.

        Refuse unit continuation/specifier syntax rather than guessing at systemd
        parsing. Environment files never get sourced or returned in diagnostics.
        """
        if p.config_path != "/etc/wazuh-indexer/opensearch.yml":
            raise SetupError("config_unsupported")
        settings = {}
        environment = {}
        start = []
        for line in unit.decode().splitlines():
            if line.strip().startswith(("#", ";")) or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key == "ExecStart":
                start.append(value)
            if key not in {"Environment", "EnvironmentFile"}:
                continue
            if "\\" in value or "%" in value:
                raise SetupError("host_unsupported")
            words = shlex.split(value)
            if key == "Environment":
                for word in words:
                    name, sep, selected = word.partition("=")
                    if sep and name in {"OPENSEARCH_PATH_CONF", "WAZUH_INDEXER_PATH_CONF"}:
                        settings[name] = selected
            else:
                for word in words:
                    optional = word.startswith("-")
                    path = word.removeprefix("-")
                    if not re.fullmatch(r"/etc/(?:default|sysconfig)/wazuh-indexer", path):
                        raise SetupError("host_unsupported")
                    if self.fs.trusted(path, missing=True) is None:
                        if not optional:
                            raise SetupError("host_unsupported")
                        environment[path] = None
                        continue
                    body = self.fs.read(path)
                    environment[path] = sha(body)
                    for entry in body.decode().splitlines():
                        entry = entry.strip()
                        if not entry or entry.startswith(("#", ";")):
                            continue
                        name, sep, selected = entry.partition("=")
                        if sep and name.strip() in {"OPENSEARCH_PATH_CONF", "WAZUH_INDEXER_PATH_CONF"}:
                            pieces = shlex.split(selected)
                            if len(pieces) != 1:
                                raise SetupError("host_unsupported")
                            settings[name.strip()] = pieces[0]
        if (len(start) != 1 or not start[0].startswith("/usr/share/wazuh-indexer/bin/systemd-entrypoint ") or
                any("path.conf" in token.lower() or "path_conf" in token.lower() or token.startswith(("-E", "--config"))
                    for token in shlex.split(start[0])[1:]) or
                settings.get("OPENSEARCH_PATH_CONF") != "/etc/wazuh-indexer" or
                any(value != "/etc/wazuh-indexer" for value in settings.values())):
            raise SetupError("host_unsupported")
        return environment

    def capture(self, p, facts, work):
        # Revalidate the release before copying anything; only manifest files
        # can enter the installed privileged interpreter tree.
        files = self.bundle_files()
        if {name: sha(body) for name, body in files.items()} != facts["bundle"]:
            raise SetupError("state_changed")
        config = self.vread(p.config_path)
        if sha(config) != facts["config"] or identity(self.vstat(p.config_path)) != facts["config_metadata"]:
            raise SetupError("state_changed")
        unit = self.fs.read(facts["unit_path"])
        if sha(unit) != facts["unit"] or stable_firewall(self.firewall()) != facts["firewall"]:
            raise SetupError("state_changed")
        self.revalidate_firewall_facts(facts)
        if self.read_firewall_compatibility() is not None:
            raise SetupError("ufw_drift")
        record = (compatibility_record(p, facts["ufw_compatibility"])
                  if facts["ufw_compatibility"] is not None else None)
        self.fs.write(work / "ufw-compatibility.json", encoded(record))
        patched = patch_http_config(config, p)
        self.fs.write(work / "original.yml", config)
        self.fs.write(work / "original-metadata.json", encoded(facts["config_metadata"]))
        self.fs.write(work / "patched.yml", patched)
        self.fs.write(work / "original-unit.service", unit)
        self.fs.write(work / "original-firewall.json", encoded(facts["firewall"]))
        self.fs.write(work / "original-unit-properties.json", encoded(facts["unit_properties"]))
        return {"original_sha256": sha(config), "patched_sha256": sha(patched),
                "metadata": facts["config_metadata"], "uid": self.uid, "gid": self.gid,
                "guard_unit_absent": True, "dropin_absent": True, "table_absent": True,
                "ufw_compatibility_original": None, "ufw_compatibility_sha256": sha(encoded(record))}

    def stage(self, p, facts, work):
        self.revalidate_firewall_facts(facts)
        with self.fs.archive(p.ca_archive, facts["archive"]) as stream:
            ca, key = read_vendor_ca_archive(stream, p)
        if ca != self.vread(p.ca_path):
            raise SetupError("certificate_invalid")
        try:
            cert, http_key = create_http_certificate(work, p, ca, key, self.vread(p.leaf_path))
        finally:
            # Signing helper unlinks temporary CA/key on all exits, including
            # interruption. No signing key is written by this coordinator.
            del key
        self.fs.write(work / "http.pem", cert)
        self.fs.write(work / "http-key.pem", http_key)
        return {"certificate_sha256": sha(cert), "key_sha256": sha(http_key), "bundle": facts["bundle"],
                "ufw_compatibility": facts["ufw_compatibility"]}

    def install(self, p, staged, work):
        files = self.bundle_files()
        if {name: sha(body) for name, body in files.items()} != staged["bundle"]:
            raise SetupError("state_changed")
        self.fs.mkdir(INSTALL_ROOT)
        self.fs.mkdir(INSTALL_ROOT / "https_setup")
        for name, body in files.items():
            self.fs.write(INSTALL_ROOT / name, body)
        self.fs.mkdir(PROFILE_ROOT)
        self.fs.write(PROFILE, encoded(p.as_dict()))
        self.install_firewall_compatibility(p, staged["ufw_compatibility"])
        self.fs.vendor_mkdir(HTTP_ROOT, self.uid, self.gid)
        self.fs.vendor_mkdir(HTTP_ROOT / "tls", self.uid, self.gid)
        for name, pin in (("http.pem", "certificate_sha256"), ("http-key.pem", "key_sha256")):
            body = self.fs.read(work / name, private=True)
            if sha(body) != staged[pin]:
                raise SetupError("state_changed")
            self.fs.vendor_write(HTTP_ROOT / "tls" / ("indexer-" + name), body, self.uid, self.gid)

    def ensure_guard(self, p):
        self.verify_installed_firewall_compatibility(p)
        table = self.table(self.firewall())
        if table["nftables"]:
            verify_table(table, p)
            return
        # Exclusive table creation and all policy objects share one nft batch.
        # A racing table creator aborts it without appending to an existing table.
        script = firewall_create_text(p).encode()
        self.run("nft", "--check", "--file", "-", data=script)
        self.run("nft", "--file", "-", data=script)
        self.verify_guard(p)

    def verify_guard(self, p):
        self.verify_installed_firewall_compatibility(p)
        verify_table(self.table(self.firewall()), p)

    def install_units(self, p, work):
        self.fs.write(GUARD_UNIT, guard_unit().encode())
        if not DROPIN.parent.exists():
            self.fs.mkdir(DROPIN.parent, mode=0o755)
        self.fs.write(DROPIN, indexer_dropin().encode())
        self.run("systemctl", "daemon-reload")
        self.run("systemd-analyze", "verify", str(GUARD_UNIT), "wazuh-indexer.service")
        props = self.properties("wazuh-indexer.service", ("DropInPaths", "ExecStartPre", "Requires", "After", "Wants"))
        if (props["DropInPaths"].split() != [str(DROPIN)] or
                ENTRYPOINT not in props["ExecStartPre"] or "guard-verify" not in props["ExecStartPre"] or
                "aegis-wazuh-http-guard.service" not in props["Requires"].split() or
                "aegis-wazuh-http-guard.service" not in props["After"].split() or
                "ufw.service" not in props["After"].split() or
                any("ufw.service" in props[k].split() for k in ("Requires", "Wants"))):
            raise SetupError("host_unsupported")
        guard = self.properties("aegis-wazuh-http-guard.service", ("After", "Before", "Requires", "Wants"))
        if ("ufw.service" not in guard["After"].split() or
                "wazuh-indexer.service" not in guard["Before"].split() or
                any("ufw.service" in guard[k].split() for k in ("Requires", "Wants"))):
            raise SetupError("host_unsupported")
        self.verify_installed_firewall_compatibility(p)
        self.run("systemctl", "enable", "--now", "aegis-wazuh-http-guard.service")
        self.verify_guard(p)

    def patch_config(self, p, work):
        original = self.fs.read(work / "original.yml", private=True)
        body = self.fs.read(work / "patched.yml", private=True)
        if body != patch_http_config(original, p):
            raise SetupError("state_changed")
        info = self.vstat(p.config_path)
        if identity(info) != json.loads(self.fs.read(work / "original-metadata.json", private=True)):
            raise SetupError("vendor_drift")
        self.fs.vendor_write(p.config_path, body, self.uid, self.gid, owner=info.st_uid,
                             group=info.st_gid, mode=stat.S_IMODE(info.st_mode), expected={sha(original)})

    def restart(self):
        self.run("systemctl", "restart", "wazuh-indexer.service")

    def verify(self, p, facts, work, *, restored=False):
        self.uid, self.gid = facts["uid"], facts["gid"]
        verify_listeners(self.run("ss", "-H", "-ltn").decode(), p, expanded=not restored)
        expected_config = self.fs.read(work / ("original.yml" if restored else "patched.yml"), private=True)
        if self.vread(p.config_path) != expected_config or sha(self.fs.read(facts["unit_path"])) != facts["unit"]:
            raise SetupError("verification_failed")
        if self.startup_environment(self.fs.read(facts["unit_path"]), p) != facts["environment_files"]:
            raise SetupError("state_changed")
        for path, saved in facts["retained"].items():
            if identity(self.vstat(path)) != saved["metadata"] or (
                    not saved["private"] and sha(self.vread(path)) != saved["sha256"]):
                raise SetupError("verification_failed")
        baseline = stable_firewall(self.firewall())
        own = self.table(baseline)
        without = {"nftables": [obj for obj in baseline["nftables"] if obj not in own["nftables"]]}
        if without != facts["firewall"]:
            raise SetupError("firewall_mismatch")
        if not restored:
            self.verify_guard(p)
        ca = self.vread(p.ca_path)
        context = ssl.create_default_context(cadata=ca.decode("ascii"))
        with socket.create_connection(("127.0.0.1", 9200), timeout=10) as tcp:
            with context.wrap_socket(tcp, server_hostname="127.0.0.1") as tls:
                actual = sha(tls.getpeercert(binary_form=True))
        expected = p.expected_leaf_der_sha256 if restored else sha(ssl.PEM_cert_to_DER_cert(self.fs.read(work / "http.pem").decode("ascii")))
        if actual != expected:
            raise SetupError("verification_failed")

    def restore(self, p, snapshot, work):
        # A killed process may not have persisted the coordinator's drift flag.
        # Never overwrite a pending/failed exchange's preserved vendor evidence.
        self.fs.check_publications()
        self.uid, self.gid = snapshot["uid"], snapshot["gid"]
        self.check_recovery_firewall_compatibility(p, snapshot, work)
        if not (snapshot["guard_unit_absent"] and snapshot["dropin_absent"] and snapshot["table_absent"]):
            raise SetupError("recovery_required")
        original = self.fs.read(work / "original.yml", private=True)
        if sha(original) != snapshot["original_sha256"]:
            raise SetupError("recovery_required")
        meta = snapshot["metadata"]
        if self.vread(p.config_path) != original:
            self.fs.vendor_write(p.config_path, original, self.uid, self.gid, owner=meta["uid"], group=meta["gid"],
                                 mode=stat.S_IMODE(meta["mode"]), expected={snapshot["original_sha256"], snapshot["patched_sha256"]})
        else:
            info = self.vstat(p.config_path)
            if (info.st_uid, info.st_gid, info.st_mode) != (meta["uid"], meta["gid"], meta["mode"]):
                raise SetupError("vendor_drift")
        if DROPIN.exists():
            if self.fs.read(DROPIN) != indexer_dropin().encode():
                raise SetupError("recovery_required")
            self.fs.unlink(DROPIN)
        # Keep the guard unit/rules armed until old listener and TLS verify.
        self.run("systemctl", "daemon-reload")

    def remove_guard(self, p):
        table = self.table(self.firewall())
        if table["nftables"]:
            verify_table(table, p)
        if GUARD_UNIT.exists():
            if self.fs.read(GUARD_UNIT) != guard_unit().encode():
                raise SetupError("recovery_required")
            # No ExecStop in this unit; stop/disable cannot delete the rules.
            self.run("systemctl", "disable", "--now", "aegis-wazuh-http-guard.service")
            self.fs.unlink(GUARD_UNIT)
            self.run("systemctl", "daemon-reload")
        if table["nftables"]:
            self.verify_guard(p)
            self.run("nft", "delete", "table", "inet", TABLE)
        if self.table(self.firewall())["nftables"]:
            raise SetupError("recovery_required")

    def cleanup(self, work):
        # Clean orphaned issuance work after interrupted recovery, without ever
        # reading signing material. Preserve generated leaf/key and backups.
        if not work.exists():
            return
        self.fs.trusted(work)
        allowed = {"ca.pem", "ca-key.pem", "old.pem", "http-key.pem", "http.csr", "extensions.cnf", "http.pem"}
        for directory in work.glob("issue-*"):
            self.fs.trusted(directory)
            entries = list(directory.iterdir())
            if any(entry.name not in allowed for entry in entries):
                raise SetupError("recovery_required")
            for entry in entries:
                self.fs.unlink(entry)
            directory.rmdir()
            fsync_directory(work)

    def guard(self, profile_path, *, ensure):
        self.require_root()
        if self.bundle != INSTALL_ROOT or str(profile_path) != PROFILE:
            raise SetupError("installed_only")
        self.bundle_files()
        p = load_profile(self.fs.read(PROFILE, private=True, limit=16384))
        self.ensure_guard(p) if ensure else self.verify_guard(p)
        return {"status": "guard_verified"}
