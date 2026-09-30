# Generic staged recovery workflow

Use this as a template. A real recovery requires a private site inventory,
known-good backup, current hardware identity, and qualified operator. Keep
the original disks and running services available for an independent rollback.

1. **Unlock and verify.** Obtain the authorized decryption material from the
   site's secret store. Verify the archive's separately held digest, then run
   `manifest-verify` and the relevant SQLite integrity checks. Treat an unknown
   or mismatched result as a stop, not as permission to edit the manifest.
2. **Identify the target.** Record host, physical ports, disk serials, VM NIC
   order, software versions, IP and cloud/tunnel identities. Never infer a
   physical port from a guest interface name or a historical VM number.
3. **Build isolated foundations.** Restore hypervisor, storage, time and a
   management path first. Keep the old and new identity from being online at
   the same time. Test basic routing and a local console before changing
   remote dependencies.
4. **Restore gateway and network roles.** Import the matching router's native
   configuration; verify WAN/LAN, emergency DNS and routes. Restore the one
   authorized DHCP owner, then each DNS, VPN, and policy role in dependency
   order. Do not create a second DHCP owner or change media paths merely to
   make monitoring available.
5. **Restore data and applications.** Match architecture and image digest,
   mount source, ownership, mode, application version and database identity.
   Start read-only services before their one writer. Apply one Compose service
   at a time with explicit scope; never globally prune production volumes.
6. **Restore management and cloud.** Bring up the management plane after local
   site functions. Confirm authorization at public edges and that local
   services remain useful with the manager or tunnel offline.
7. **Accept and cut over.** Test a fresh client lease, gateway, DNS, routing,
   each site's application behavior, archive acknowledgment, capacity growth,
   and a real media session if media is in scope. Process/HTTP health alone is
   insufficient. Record before/after, operator, exact version and per-site
   results. If a write has an unknown outcome, read back independently before
   deciding whether to retry or roll back.

This public template contains no device-specific shell commands. Keep exact
target disk commands and site secrets in private, reviewed runbooks.
