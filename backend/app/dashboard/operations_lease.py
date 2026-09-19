"""Cross-process root ownership. OS locks disappear on crash; evidence does not."""
import hashlib
import json
import os

from .operations_config import OperationsError, local_path
from ..intake.io import read_local
from ..intake.errors import IntakeError


class RootLease:
    def __init__(self, config):
        self.fd = None
        root = local_path(config.output_root, directory=True)
        path = root / '.operations.lock'
        try:
            if path.exists():
                if local_path(path).stat().st_nlink != 1:
                    raise OperationsError('invalid_path')
            self.fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            if os.fstat(self.fd).st_size == 0:
                os.write(self.fd, b'0')
            os.lseek(self.fd, 0, os.SEEK_SET)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.close()
            raise OperationsError('root_in_use') from None
        try:
            # No secrets in binding. Reject accidental reuse under another scope.
            identity = json.dumps({'environment_id': config.environment_id,
                'agent_ids': sorted(config.agent_ids), 'index': config.index}, sort_keys=True).encode()
            digest = hashlib.sha256(identity).hexdigest().encode('ascii')
            binding = root / '.operations-scope'
            if binding.exists():
                if read_local(binding, limit=64, stage='inputs') != digest:
                    raise OperationsError('root_scope_mismatch')
            else:
                with binding.open('xb') as stream:
                    stream.write(digest)
                    stream.flush()
                    os.fsync(stream.fileno())
        except (OSError, IntakeError, OperationsError):
            self.close()
            raise OperationsError('root_scope_mismatch') from None

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
