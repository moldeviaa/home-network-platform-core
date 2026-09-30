"""Bounded read-only inspection of tar archives before isolated restoration."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import tarfile

from .manifest import MAX_ARTIFACT_BYTES, RecoveryError, relative_parts, require


DEFAULT_MAX_MEMBERS = 100_000
DEFAULT_MAX_UNPACKED_BYTES = 4 * 1024 ** 4


def audit_tar(
    archive: Path,
    *,
    max_members: int = DEFAULT_MAX_MEMBERS,
    max_unpacked_bytes: int = DEFAULT_MAX_UNPACKED_BYTES,
) -> dict:
    """Read every regular member without extracting; reject links and unsafe paths.

    A successful audit is a structural check of this archive, not evidence that
    its contents are trustworthy, complete, or suitable for a live target.
    """
    require(type(max_members) is int and 0 < max_members <= DEFAULT_MAX_MEMBERS,
            "member_limit")
    require(type(max_unpacked_bytes) is int
            and 0 < max_unpacked_bytes <= DEFAULT_MAX_UNPACKED_BYTES,
            "unpacked_limit")
    archive = Path(archive).absolute()
    info = archive.lstat()
    require(stat.S_ISREG(info.st_mode) and not archive.is_symlink()
            and info.st_nlink == 1 and info.st_size <= MAX_ARTIFACT_BYTES,
            "archive_not_regular")

    seen: dict[str, str] = {}
    members = 0
    directories = 0
    files = 0
    total = 0
    try:
        descriptor = os.open(archive, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb", buffering=0) as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_size == info.st_size, "archive_changed")
            with tarfile.open(fileobj=stream, mode="r|*") as handle:
                for member in handle:
                    members += 1
                    require(members <= max_members, "too_many_members")
                    name = member.name.rstrip("/") if member.isdir() else member.name
                    parts = relative_parts(name)
                    require(name not in seen, "duplicate_member")
                    for index in range(1, len(parts)):
                        require(seen.get("/".join(parts[:index])) != "file",
                                "file_as_parent")
                    if member.isdir():
                        require(member.type == tarfile.DIRTYPE,
                                "unsupported_member_type")
                        seen[name] = "directory"
                        directories += 1
                        continue
                    require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE),
                            "unsupported_member_type")
                    require(not any(key.startswith("GNU.sparse")
                                    for key in member.pax_headers), "sparse_member")
                    require(not any(existing.startswith(name + "/") for existing in seen),
                            "file_as_parent")
                    require(0 <= member.size <= max_unpacked_bytes - total,
                            "unpacked_limit")
                    extracted = handle.extractfile(member)
                    require(extracted is not None, "member_unreadable")
                    count = 0
                    while True:
                        block = extracted.read(min(1024 * 1024, member.size - count + 1))
                        if not block:
                            break
                        count += len(block)
                        require(count <= member.size, "member_size_mismatch")
                    require(count == member.size, "member_size_mismatch")
                    total += count
                    files += 1
                    seen[name] = "file"
            after = os.fstat(stream.fileno())
    except (tarfile.TarError, EOFError) as exc:
        raise RecoveryError("tar_invalid") from exc
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "archive_changed")
    return {"audited": True, "members": members, "directories": directories,
            "files": files, "unpacked_bytes": total, "extracted": False}
