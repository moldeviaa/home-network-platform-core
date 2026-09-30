"""Small, offline command-line interface for recovery artifact checks."""

from __future__ import annotations

import argparse
import json
import sys

from .manifest import RecoveryError, verify_manifest, write_manifest
from .tar_audit import audit_tar


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="home-net-recovery")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("manifest-create", help="create an exclusive manifest")
    create.add_argument("root")
    create.add_argument("--filename", default="manifest.json")
    verify = commands.add_parser("manifest-verify", help="verify every listed artifact")
    verify.add_argument("root")
    verify.add_argument("--filename", default="manifest.json")
    verify.add_argument("--sqlite", action="append", default=[], metavar="RELATIVE_PATH")
    verify.add_argument("--allow-extra", action="store_true")
    tar = commands.add_parser("tar-audit", help="inspect tar members without extraction")
    tar.add_argument("archive")
    tar.add_argument("--max-members", type=int, default=100_000)
    tar.add_argument("--max-unpacked-bytes", type=int, default=4 * 1024 ** 4)
    args = parser.parse_args(argv)
    try:
        if args.command == "manifest-create":
            result = write_manifest(args.root, filename=args.filename)
            output = {"created": True, "files": result["file_count"],
                      "bytes": result["total_bytes"]}
        elif args.command == "manifest-verify":
            output = verify_manifest(args.root, filename=args.filename,
                                     sqlite_names=tuple(args.sqlite),
                                     strict=not args.allow_extra)
        else:
            output = audit_tar(args.archive, max_members=args.max_members,
                               max_unpacked_bytes=args.max_unpacked_bytes)
    except (RecoveryError, OSError) as exc:
        code = str(exc) if isinstance(exc, RecoveryError) else "filesystem_error"
        print(json.dumps({"ok": False, "error": code}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps({"ok": True, **output}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
