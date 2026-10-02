# Application-owned MSAL

`home_net_auth.MsalAuth` orchestrates a confidential-client authorization-code
flow and silent token renewal. Install the optional dependencies with
`python3 -m pip install --require-hashes --only-binary=:all: -r requirements-auth.txt`
for reproducible tests, or install this package's `auth` extra in your application.
The locked SDK is MSAL 1.38.0. No discovery or network call runs during readiness.

Every consumer supplies these arguments explicitly:

| Input | Contract |
| --- | --- |
| `FlowPolicy` | Tenant UUID, allowed operator object UUID/email, HTTPS public origin, `__Host-` flow-cookie name, authentication label and logout path. Microsoft public/US/China authorities are allowed. There is no default user or tenant. |
| `settings` | An object with `audience`, `session_seconds` (60–21600), `client_secret_file`, `scope` (`api://RESOURCE_UUID/Scope.Name`) and an application-generated 64-hex `binding`. The human resource must differ from the client. |
| `identity_verifier` | A ready, trusted signed ID-token verifier with `authenticate([token], expected_nonce=..., require_owner_email=True)`. It must verify RS256/JWKS selection, fixed issuer/client audience, tenant/operator, email and lifetime, and return the identity DTO below. SDK decoded claims are insufficient. |
| `resource_verifier` | A trusted delegated access-token verifier with `authenticate(token)`. It must check signature, issuer, resource audience, authorized client, required delegated scope, operator/tenant and lifetime. Application-only and wrong-resource tokens must fail. It returns `tenant`, `object_id`, `expires_at`, `issued_at`. |
| `identity_factory` | A dataclass constructor with positional fields `issuer, audience, subject, email, tenant, object_id, expires_at, issued_at, binding, session_seconds, authentication, logout_url`. ID identities must support `dataclasses.replace`. |

Never inject an unverified JWT decoder. These verifiers are mandatory, are trusted
application code, and are not created from browser input. The engine additionally
checks that their identities match each other and the explicit operator policy.
`home_net_validation.rsa_verifier()` is a signature primitive, **not** a complete
token verifier. It cannot establish authorization by itself.

Call `begin()` to obtain `(authorization_url, flow_cookie_value)`. Return the URL
as a redirect and the cookie via the instance's `cookie_header(value)`, without
logging either. `complete(raw_query, raw_cookie_header)` consumes the state before
the token exchange and returns `MsalGrant`: independently verified identity,
serialized SDK cache and bound account. Failed exchanges cannot replay a state.
Flows expire after five minutes and at most 64 flows/pending requests exist.

The caller owns persistent sessions, CSRF, rate limiting at the HTTP boundary,
logout, and encrypted cache storage. Serialize renewals for each session before
calling `renew(cache_state, account, original_id_subject)`. A resource's pairwise
`sub` does not replace the original ID subject. Persist the returned cache only
under the same authenticated session/account/policy binding. Tokens are not
returned to browsers or printed by this library. Secret files must be separate,
private, operator/root-owned regular files; the library has no configured path.

`ReauthenticationRequired` distinguishes interaction from transient provider
failure. Its bounded claims hint remains server-side; feed it to a new `begin`
only after invalidating the affected session as appropriate. Other `AuthError`
instances expose only HTTP status and fixed code. No local sign-in-frequency
deadline, unconditional login prompt, or automatic token POST retry is added.

The production transport accepts only the tenant's exact HTTPS discovery/token
paths, refuses redirects/proxy environment, limits JSON to 128 KiB and sanitizes
provider errors before handing them to the SDK. The cache hook removes code and
PKCE verifier from events the SDK may log. Consumer request logging must also
exclude callbacks, cookies, authorization URLs, tokens and SDK cache bytes.

The tests inject synthetic verifiers to exercise orchestration and use generated
RSA keys for validation primitives. They make no real identity-provider calls.
Real application verifiers, browser/session integration, sovereign-cloud service
behavior and production credentials require separate consumer validation.
