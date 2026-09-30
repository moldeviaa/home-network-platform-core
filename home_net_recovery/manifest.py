"""Create and verify an exact, offline manifest without reading artifact content aloud."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat


SCHEMA = "home-net-recovery-manifest/v1"
MAX_FILES = 100_000
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 4 * 1024 ** 4


class RecoveryError(ValueError):
    """A bounded validation failed; its code never contains artifact bytes."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise RecoveryError(code)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("utf-8")


def decode_document(raw: bytes) -> dict:
    require(0 < len(raw) <= MAX_MANIFEST_BYTES, "manifest_size")

    def unique(pairs):
        output = {}
        for key, value in pairs:
            require(key not in output, "duplicate_json_key")
            output[key] = value
        return output

    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: require(False, "nonfinite_json"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RecoveryError("manifest_json") from exc
    require(type(value) is dict and canonical(value) == raw, "manifest_not_canonical")
    return value


def relative_parts(name: str) -> tuple[str, ...]:
    require(type(name) is str and 0 < len(name) <= 4096 and "\\" not in name
            and not any(ord(char) < 32 or ord(char) == 127 for char in name)
            and not name.startswith("/"), "unsafe_path")
    parts = tuple(name.split("/"))
    require(all(part not in ("", ".", "..") for part in parts), "unsafe_path")
    return parts


def root_directory(root: Path) -> Path:
    root = Path(root).absolute()
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and not root.is_symlink(), "root_directory")
    return root


def safe_file(root: Path, name: str) -> Path:
    path = root
    parts = relative_parts(name)
    for part in parts[:-1]:
        path = path / part
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and not path.is_symlink(), "linked_or_missing_parent")
    path = path / parts[-1]
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_nlink == 1,
            "artifact_not_regular")
    return path


def digest_file(root: Path, name: str) -> tuple[int, str]:
    path = safe_file(root, name)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb", buffering=0) as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 <= before.st_size <= MAX_ARTIFACT_BYTES, "artifact_size")
        digest = hashlib.sha256()
        length = 0
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            length += len(block)
            require(length <= before.st_size, "artifact_changed")
            digest.update(block)
        after = os.fstat(stream.fileno())
    identity = lambda item: (item.st_dev, item.st_ino, item.st_nlink, item.st_size,
                             item.st_mtime_ns, item.st_ctime_ns)
    require(length == before.st_size and identity(before) == identity(after)
            and identity(after) == identity(path.lstat()), "artifact_changed")
    return length, digest.hexdigest()


def inventory(root: Path, *, omit: str = "manifest.json") -> list[str]:
    root = root_directory(root)
    names: list[str] = []
    for directory, folders, files in os.walk(root, topdown=True, followlinks=False):
        folders.sort()
        files.sort()
        parent = Path(directory)
        for folder in folders:
            item = parent / folder
            require(stat.S_ISDIR(item.lstat().st_mode) and not item.is_symlink(), "linked_directory")
        for file in files:
            item = parent / file
            name = item.relative_to(root).as_posix()
            relative_parts(name)
            if name == omit:
                continue
            require(stat.S_ISREG(item.lstat().st_mode) and not item.is_symlink()
                    and item.lstat().st_nlink == 1, "artifact_not_regular")
            names.append(name)
            require(len(names) <= MAX_FILES, "too_many_artifacts")
    require(len(set(names)) == len(names), "duplicate_artifact_path")
    return sorted(names)


def create_manifest(root: Path, *, omit: str = "manifest.json") -> dict:
    root = root_directory(root)
    rows = []
    total = 0
    for name in inventory(root, omit=omit):
        size, sha256 = digest_file(root, name)
        rows.append({"path": name, "size": size, "sha256": sha256})
        total += size
    return {"schema": SCHEMA, "version": 1, "file_count": len(rows),
            "total_bytes": total, "files": rows}


def write_manifest(root: Path, *, filename: str = "manifest.json") -> dict:
    root = root_directory(root)
    require(len(relative_parts(filename)) == 1, "manifest_filename")
    result = create_manifest(root, omit=filename)
    raw = canonical(result)
    require(len(raw) <= MAX_MANIFEST_BYTES, "manifest_size")
    path = root / filename
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    return result


def sqlite_integrity(root: Path, names: list[str]) -> None:
    for name in names:
        path = safe_file(root, name)
        require(path.suffix.lower() in (".sqlite", ".sqlite3", ".db"), "sqlite_suffix")
        uri = path.as_uri() + "?mode=ro&immutable=1"
        try:
            with sqlite3.connect(uri, uri=True) as database:
                require(database.execute("PRAGMA integrity_check").fetchall() == [("ok",)],
                        "sqlite_integrity")
        except sqlite3.DatabaseError as exc:
            raise RecoveryError("sqlite_integrity") from exc


def verify_manifest(root: Path, *, filename: str = "manifest.json",
                    sqlite_names: tuple[str, ...] = (), strict: bool = True) -> dict:
    root = root_directory(root)
    require(len(relative_parts(filename)) == 1, "manifest_filename")
    manifest_path = safe_file(root, filename)
    require(manifest_path.stat().st_size <= MAX_MANIFEST_BYTES, "manifest_size")
    manifest = decode_document(manifest_path.read_bytes())
    require(set(manifest) == {"schema", "version", "file_count", "total_bytes", "files"}
            and manifest["schema"] == SCHEMA and type(manifest["version"]) is int
            and manifest["version"] == 1 and type(manifest["files"]) is list
            and type(manifest["file_count"]) is int
            and 0 <= manifest["file_count"] <= MAX_FILES
            and type(manifest["total_bytes"]) is int
            and 0 <= manifest["total_bytes"] <= MAX_ARTIFACT_BYTES * MAX_FILES,
            "manifest_shape")
    names = []
    total = 0
    for row in manifest["files"]:
        require(type(row) is dict and set(row) == {"path", "size", "sha256"}
                and type(row["size"]) is int and 0 <= row["size"] <= MAX_ARTIFACT_BYTES
                and type(row["sha256"]) is str and len(row["sha256"]) == 64
                and all(char in "0123456789abcdef" for char in row["sha256"]),
                "manifest_entry")
        name = row["path"]
        relative_parts(name)
        require(name != filename and (not names or names[-1] < name), "manifest_order")
        names.append(name)
        size, sha256 = digest_file(root, name)
        require((size, sha256) == (row["size"], row["sha256"]), "artifact_mismatch")
        total += size
    require(len(names) == manifest["file_count"] and total == manifest["total_bytes"],
            "manifest_totals")
    if strict:
        require(inventory(root, omit=filename) == names, "unlisted_artifact")
    require(set(sqlite_names) <= set(names), "sqlite_not_in_manifest")
    sqlite_integrity(root, list(sqlite_names))
    return {"verified": True, "files": len(names), "bytes": total,
            "sqlite_checked": len(sqlite_names), "production_writes": 0}
