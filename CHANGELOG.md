# Changelog

## 0.2.0

- Add an explicitly configured MSAL authorization-code/PKCE engine with bounded,
  single-use login flows, independently supplied signed identity/resource
  verifiers, fixed-endpoint transport and account-bound silent renewal.
- Add bounded strict JSON, canonical base64url, RS256 signature primitives and
  owned private-file validation. No identity, private path or credential defaults.
- Keep recovery APIs and CLI compatible with 0.1.0. Authentication dependencies
  are optional and pinned for reproducible tests.
- Establish independently reviewed public releases and explicit private consumer
  compatibility checks.

## 0.1.0

- Offline recovery manifests, trusted manifest pins, SQLite snapshot integrity
  checks and streaming tar path/type/size audits.
