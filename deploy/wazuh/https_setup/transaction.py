"""Durable single-host transaction. Journals contain no key or command output."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat

from .contracts import Profile, SetupError

STATE_ROOT = Path("/var/backups/aegis-wazuh-https")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path, body, *, mode=0o600, uid=None, gid=None, sync_directory=fsync_directory):
    """Caller first verifies the root-owned, non-writable ancestor chain."""
    path = Path(path)
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(12))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            if uid is not None:
                os.fchown(stream.fileno(), uid, gid)
            os.fchmod(stream.fileno(), mode) if hasattr(os, "fchmod") else os.chmod(temporary, mode)
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


class DurableStore:
    """No I/O at construction; check/status never create a lock or directory.

    The host validates the state path before mutation. Linux files are checked
    again here; the directory is never recursively removed during recovery.
    """
    def __init__(self, root=STATE_ROOT, *, sync_directory=fsync_directory):
        self.root = Path(root)
        self.sync_directory = sync_directory

    def _trusted(self, path):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or (os.name == "posix" and
                (info.st_uid != os.geteuid() or info.st_mode & 0o077)):
            raise SetupError("path_untrusted")
        if not stat.S_ISDIR(info.st_mode) and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
            raise SetupError("path_untrusted")

    def read(self):
        if not self.root.exists():
            return None
        self._trusted(self.root)
        path = self.root / "intent.json"
        if not path.exists():
            return None
        self._trusted(path)
        with path.open("rb") as stream:
            raw = stream.read(4 * 1024 * 1024 + 1)
        try:
            value = json.loads(raw)
            if len(raw) > 4 * 1024 * 1024 or type(value) is not dict or value.get("schema_version") != 1:
                raise ValueError
            if value["status"] not in {"in_progress", "pending_external_validation", "rolled_back", "recovery_required"}:
                raise ValueError
            if not isinstance(value["id"], str) or len(value["id"]) != 32 or any(c not in "0123456789abcdef" for c in value["id"]):
                raise ValueError
            return value
        except (ValueError, KeyError, TypeError):
            raise SetupError("recovery_required") from None

    def save(self, intent):
        self._trusted(self.root)
        atomic_write(self.root / "intent.json", encoded(intent), sync_directory=self.sync_directory)
        # Fixed phase/status vocabulary only, never raw exception/command text.
        path = self.root / "recovery.jsonl"
        if path.exists():
            self._trusted(path)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "ab") as stream:
            stream.write(encoded({k: intent[k] for k in ("id", "phase", "status")}) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        self.sync_directory(self.root)

    @contextmanager
    def lock(self):
        if not self.root.exists():
            self.root.mkdir(mode=0o700)
            self.sync_directory(self.root.parent)
        self._trusted(self.root)
        path = self.root / "operator.lock"
        if path.exists():
            self._trusted(path)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        acquired = False
        try:
            try:
                if os.name == "posix":
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:
                    import msvcrt
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                acquired = True
            except OSError:
                raise SetupError("operation_locked") from None
            yield
        finally:
            if acquired:
                if os.name == "posix":
                    fcntl.flock(fd, fcntl.LOCK_UN)
                else:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            os.close(fd)

    def work(self, intent):
        return self.root / intent["id"]

    def create_work(self, intent):
        work = self.work(intent)
        work.mkdir(mode=0o700)
        self.sync_directory(self.root)
        return work


class Coordinator:
    def __init__(self, host, store=None):
        self.host = host
        self.store = store if store is not None else DurableStore()

    def check(self, profile_path):
        p, profile_hash, facts = self.host.preflight(profile_path)
        return {"status": "ready", "profile_sha256": profile_hash,
                "check_sha256": digest({"profile_sha256": profile_hash, "facts": facts}), "facts": facts}

    def status(self):
        intent = self.store.read()
        return {"status": intent["status"], "phase": intent["phase"]} if intent else {"status": "not_applied"}

    def _phase(self, intent, phase):
        intent["phase"] = phase
        self.store.save(intent)

    def apply(self, profile_path, profile_hash, check_hash):
        self.host.prepare_state()
        with self.store.lock():
            if self.store.read() is not None:
                # Even completed rollback requires explicit operator disposition
                # of retained backups before a fresh deployment.
                raise SetupError("intent_exists")
            p, actual_profile, facts = self.host.preflight(profile_path)
            if actual_profile != profile_hash or digest({"profile_sha256": actual_profile, "facts": facts}) != check_hash:
                raise SetupError("state_changed")
            intent = {"schema_version": 1, "id": secrets.token_hex(16), "profile": p.as_dict(),
                      "profile_sha256": actual_profile, "facts": facts, "phase": "prepare",
                      "status": "in_progress", "snapshot": None}
            self.store.save(intent)
            work = self.store.work(intent)
            try:
                self.store.create_work(intent)
                self._phase(intent, "backup")
                intent["snapshot"] = self.host.capture(p, facts, work)
                self._phase(intent, "stage")
                staged = self.host.stage(p, facts, work)
                self._phase(intent, "install")
                self.host.install(p, staged, work)
                self._phase(intent, "guard")
                self.host.ensure_guard(p)
                self.host.verify_guard(p)
                self._phase(intent, "units")
                self.host.install_units(p, work)
                self._phase(intent, "patch")
                self.host.verify_guard(p)
                self.host.patch_config(p, work)
                self._phase(intent, "restart")
                self.host.verify_guard(p)
                self.host.restart()
                self._phase(intent, "verify")
                self.host.verify(p, facts, work)
                intent["status"] = "pending_external_validation"
                self._phase(intent, "complete")
                return self.status()
            except Exception as exc:
                if isinstance(exc, SetupError) and exc.code in {"ufw_drift", "ufw_unsupported"}:
                    intent["preserve_policy_evidence"] = True
                    intent["status"] = "recovery_required"
                    self.store.save(intent)
                    raise SetupError("recovery_required") from None
                if isinstance(exc, SetupError) and exc.code in {"vendor_drift", "filesystem_unsupported"}:
                    # Do not turn a refused publication into an overwrite via
                    # generic restore. Manual evidence reconciliation is needed.
                    intent["preserve_vendor_edits"] = True
                    intent["status"] = "recovery_required"
                    self.store.save(intent)
                    raise SetupError("filesystem_unsupported" if exc.code == "filesystem_unsupported" else "recovery_required") from None
                self._recover(intent)
                raise SetupError("verification_failed") from None
            except BaseException:
                intent["status"] = "recovery_required"
                self.store.save(intent)
                raise SetupError("recovery_required") from None
            finally:
                self.host.cleanup(work)

    def rollback(self):
        self.host.prepare_state()
        with self.store.lock():
            intent = self.store.read()
            if intent is None:
                raise SetupError("no_intent")
            if intent["status"] != "rolled_back":
                self._recover(intent)
            return self.status()

    def _recover(self, intent):
        if intent.get("preserve_vendor_edits") or intent.get("preserve_policy_evidence"):
            raise SetupError("recovery_required")
        p = Profile(**intent["profile"])
        work = self.store.work(intent)
        try:
            if intent["snapshot"] is None:
                raise SetupError("recovery_required")
            self._phase(intent, "restore")
            self.host.restore(p, intent["snapshot"], work)
            self._phase(intent, "restore_restart")
            self.host.restart()
            self._phase(intent, "restore_verify")
            self.host.verify(p, intent["facts"], work, restored=True)
            self._phase(intent, "remove_guard")
            self.host.remove_guard(p)
            self._phase(intent, "restore_compatibility")
            self.host.restore_firewall_compatibility(p, intent["snapshot"], work)
            intent["status"] = "rolled_back"
            self._phase(intent, "rolled_back")
        except BaseException:
            # Deletion may have succeeded despite a lost acknowledgment. Try
            # to retain/re-arm the exact owned protection on uncertain recovery;
            # conflicts still refuse and never get replaced.
            try:
                self.host.ensure_guard(p)
            except BaseException:
                pass
            intent["status"] = "recovery_required"
            self.store.save(intent)
            raise SetupError("recovery_required") from None
        finally:
            self.host.cleanup(work)
