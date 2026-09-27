"""An operator lease prevents local config/KEK edits while its server is running."""
from contextlib import contextmanager
import os
from pathlib import Path
from .files import protect


@contextmanager
def operator_lease(config_path):
    path = Path(config_path).resolve().with_suffix(".operator.lock")
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        protect(path)
        if os.fstat(descriptor).st_size == 0: os.write(descriptor, b"0")
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)
