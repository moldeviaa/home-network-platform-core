# Home Network Recovery Core

Offline checks for disaster-recovery artifacts in self-hosted networks. This
repository contains reusable code and a generic recovery sequence. It has no
site addresses, credentials, device snapshots, cloud identities, or production
deployment configuration. Keep actual backups and generated manifests in a
private, encrypted store.

Python 3.10 or newer is required. From this checkout:

```sh
python3 -m unittest discover -s tests -v
python3 -m home_net_recovery manifest-create /path/to/isolated-artifacts
python3 -m home_net_recovery manifest-verify /path/to/isolated-artifacts \
  --sqlite snapshot/site.sqlite3
python3 -m home_net_recovery tar-audit /path/to/isolated-backup.tar.gz
```

`manifest-create` creates `manifest.json` exclusively; it never overwrites an
existing manifest. The canonical JSON contains every regular file's relative
path, byte length, and SHA-256. `manifest-verify` checks the exact inventory and
can run SQLite `PRAGMA integrity_check` against a **standalone snapshot**. An
active database with WAL must first be captured by the database's supported
online backup method; checking a copied main file alone can miss committed
transactions. The manifest authenticates bytes only when its own SHA-256 or
signature is held separately and verified.

`tar-audit` streams and counts every file without extracting it. It rejects
absolute or parent-traversing paths, links, devices, duplicate paths, sparse
members and archives that exceed explicit limits. Archives with links require
an application-specific review and isolated restore. A passing audit does not
prove that files are complete, clean, or safe to apply to a live system.

The commands print counts and error codes, not artifact bytes or file names.
They make no network calls and do not write to devices or running services.
The only persistent write is an explicitly requested new manifest. See
[RESTORE_WORKFLOW.md](RESTORE_WORKFLOW.md) for an ordered recovery template.

The private companion project holds actual site definitions, encrypted restore
packages, and operation-specific runbooks. Do not copy them into this public
repository or put credentials into either Git history.
