"""Explicit owned private-file reads; no paths or values are configured here."""
import os
from pathlib import Path
import stat

def secret_path(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 4096 or
            "\x00" in value or not Path(value).is_absolute() or
            any(part in (".", "..") for part in value.split("/")) or
            str(Path(value)) != value):
        raise ValueError("An explicit absolute private client-secret file is required")
    return Path(value)


def read_client_secret(value):
    """Read only a user/root-owned private regular file, without a symlink hop."""
    path = secret_path(value)
    # A private file cannot be replaced through a writable private-directory
    # ancestor. Sticky system temporary directories remain valid for offline
    # isolated tests, provided the immediate parent is private and owned.
    for parent in (path.parent, *path.parents[1:]):
        meta = parent.lstat()
        if not stat.S_ISDIR(meta.st_mode) or stat.S_ISLNK(meta.st_mode):
            raise ValueError("Client-secret parent must be a real directory")
        if meta.st_mode & 0o022 and not (meta.st_mode & stat.S_ISVTX and meta.st_uid == 0):
            raise ValueError("Client-secret parent must not be writable by others")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as source:
        meta = os.fstat(source.fileno())
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid not in (0, os.getuid()) or
                meta.st_mode & 0o077 or meta.st_nlink != 1 or not 1 <= meta.st_size <= 4096):
            raise ValueError("Client-secret file must be owned and private")
        raw = source.read(4097)
        after = os.fstat(source.fileno())
        if (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(raw) != meta.st_size:
            raise ValueError("Client-secret file changed during read")
    if len(raw) > 4096:
        raise ValueError("Client-secret file is too large")
    try:
        value = raw.decode("ascii").removesuffix("\n")
    except UnicodeError:
        raise ValueError("Client-secret encoding is invalid") from None
    if not 16 <= len(value) <= 2048 or any(ord(char) < 33 or ord(char) > 126 for char in value):
        raise ValueError("Client-secret format is invalid")
    return value
