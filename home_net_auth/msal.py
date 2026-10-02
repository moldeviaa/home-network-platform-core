"""MSAL code flow, bounded transport, single-use login state and silent renewal.

Consumers supply signed ID/resource verifiers and their own persistent sessions.
SDK claims and proxy headers never replace those verifiers.
"""
from dataclasses import dataclass, field, replace
import base64
import hashlib
import hmac
from http.cookies import CookieError, SimpleCookie
import json
import re
import secrets
import threading
import time
from urllib.parse import parse_qsl, urlsplit

from home_net_validation import strict_json as parse_json, ValidationError
from home_net_validation.private_file import read_client_secret
from .errors import AuthError as AccessError, denied
from .policy import FlowPolicy, UUID, valid_client_id

FLOW_SECONDS = 300
MAX_FLOWS = 64
MAX_CACHE = 524288
MAX_CLAIMS = 8192
OPAQUE = re.compile(r"[A-Za-z0-9_-]{43,128}\Z")
IDENTITY_HEADERS = frozenset(("authorization", "cf-access-jwt-assertion",
                             "cf-access-authenticated-user-email", "remote-user"))


def strict_json(raw):
    try:
        return parse_json(raw)
    except ValidationError:
        denied()


def cookie_header(value="", *, cookie_name):
    if not re.fullmatch(r"__Host-[A-Za-z0-9_-]{1,64}", cookie_name) or value and not OPAQUE.fullmatch(value):
        raise ValueError("invalid_flow_cookie")
    return (cookie_name + "=" + value + "; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=" +
            str(FLOW_SECONDS if value else 0))


def checked_claims(value):
    if value is None:
        return None
    try:
        if (not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= MAX_CLAIMS or
                any(ord(char) < 32 for char in value)):
            raise ValueError()
        decoded = strict_json(value)
        if not isinstance(decoded, dict) or not decoded or set(decoded) - {"access_token", "id_token"}:
            raise ValueError()
        if any(not isinstance(part, dict) for part in decoded.values()):
            raise ValueError()
    except (AccessError, ValueError, UnicodeError):
        raise AccessError(503, "authentication_unavailable") from None
    return value


class ReauthenticationRequired(AccessError):
    """Only bounded server-held hints; string/repr never contains provider data."""
    def __init__(self, *, claims_challenge=None, prompt=None):
        if prompt not in (None, "login"):
            raise AccessError(503, "authentication_unavailable")
        try:
            self.claims_challenge = checked_claims(claims_challenge)
        except AccessError:
            # An unusable hint cannot change a definitive reauthentication
            # decision into a transient error that leaves the session active.
            self.claims_challenge = None
        self.prompt = prompt
        super().__init__(401, "reauthentication_required")


@dataclass(frozen=True)
class MsalGrant:
    identity: object
    cache_state: str = field(repr=False)
    account: dict = field(repr=False)
    previous_session_hash: str | None = field(default=None, repr=False)


def sanitized_token_response(value):
    """Keep protocol decisions while removing SDK-loggable provider text."""
    if "error" not in value:
        return {key: item for key, item in value.items() if key not in ("error_description", "error_uri")}
    errors = {"invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type",
              "invalid_scope", "interaction_required", "login_required", "consent_required", "access_denied",
              "temporarily_unavailable", "server_error"}
    error = value.get("error")
    clean = {"error": error if isinstance(error, str) and error in errors else "server_error"}
    suberror = value.get("suberror")
    if isinstance(suberror, str) and suberror in {"basic_action", "additional_action", "consent_required",
            "user_password_expired", "bad_token", "token_expired", "protection_policy_required",
            "client_mismatch", "device_authentication_failed"}:
        clean["suberror"] = suberror
    codes = value.get("error_codes")
    if isinstance(codes, list) and len(codes) <= 16 and all(type(code) is int and 0 <= code <= 1000000000 for code in codes):
        clean["error_codes"] = codes
    try:
        claims = checked_claims(value.get("claims"))
    except AccessError:
        claims = None
    if claims is not None:
        clean["claims"] = claims
    for key in ("correlation_id", "trace_id"):
        if isinstance(value.get(key), str) and UUID.fullmatch(value[key]):
            clean[key] = value[key]
    return clean


def checked_account(value, policy):
    keys = ("home_account_id", "environment", "realm", "local_account_id")
    if (not isinstance(value, dict) or
            any(not isinstance(value.get(key), str) or not 1 <= len(value[key]) <= 512 or
                any(ord(char) < 33 or ord(char) > 126 for char in value[key]) for key in keys) or
            value["environment"] != policy.host or value["realm"] != policy.tenant or
            value["local_account_id"] != policy.object_id):
        raise ReauthenticationRequired()
    return {key: value[key] for key in keys}


def reject_identity_headers(headers):
    for name in headers.keys():
        lowered = name.lower()
        if (lowered in IDENTITY_HEADERS or lowered.startswith("x-auth-request-") or
                lowered.startswith("x-forwarded-user") or lowered.startswith("x-forwarded-email") or
                lowered.startswith("x-forwarded-preferred-username") or lowered.startswith("x-forwarded-access-token")):
            denied()


def flow_cookie(cookie, cookie_name):
    try:
        if (not isinstance(cookie, str) or len(cookie) > 16384 or
                sum(part.strip().split("=", 1)[0] == cookie_name for part in cookie.split(";")) != 1):
            denied()
        parsed = SimpleCookie()
        parsed.load(cookie)
        value = parsed[cookie_name].value
        if not OPAQUE.fullmatch(value):
            denied()
        return value
    except (CookieError, KeyError, ValueError):
        denied()


def callback_response(query):
    if not isinstance(query, str) or not 1 <= len(query) <= 16384:
        denied()
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True,
                          encoding="utf-8", errors="strict", max_num_fields=8)
    except (ValueError, UnicodeError):
        denied()
    result = dict(pairs)
    if (len(result) != len(pairs) or set(result) -
            {"state", "code", "session_state", "client_info", "error", "error_description", "error_uri"} or
            not OPAQUE.fullmatch(result.get("state", "")) or
            any(not value or len(value) > 8192 or any(ord(char) < 32 for char in value) for value in result.values()) or
            ("code" in result) == ("error" in result)):
        denied()
    # Entra can return optional base64url client_info with the authorization
    # code. It is protocol metadata, never an identity or an allowlist input.
    if "client_info" in result and (len(result["client_info"]) > 2048 or
            not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", result["client_info"])):
        denied()
    return result


class MsalAuth:
    def __init__(self, settings, policy, *, identity_verifier, resource_verifier, identity_factory,
                 factory=None, clock=time.time, monotonic=time.monotonic):
        if not isinstance(policy, FlowPolicy):
            raise ValueError("explicit_flow_policy_required")
        self.clock, self.monotonic, self.policy = clock, monotonic, policy
        self.settings, self.verifier, self.human_verifier = None, None, None
        self._factory, self._msal, self._requests = factory, None, None
        self._identity_factory = identity_factory
        self._lock, self._flows, self._pending = threading.Lock(), {}, 0
        if (identity_verifier is None or resource_verifier is None or not callable(identity_factory) or
                not callable(getattr(identity_verifier, "authenticate", None)) or
                not callable(getattr(resource_verifier, "authenticate", None))):
            raise ValueError("trusted_verifiers_required")
        try:
            if (not valid_client_id(settings.audience) or type(settings.session_seconds) is not int or
                    not 60 <= settings.session_seconds <= 21600 or
                    not isinstance(settings.scope, str) or not re.fullmatch(r"api://[0-9a-f-]{36}/[A-Za-z][A-Za-z0-9._-]{0,127}", settings.scope) or
                    not valid_client_id(settings.scope[6:42]) or settings.scope[6:42] == settings.audience or
                    not isinstance(settings.binding, str) or not re.fullmatch(r"[0-9a-f]{64}", settings.binding)):
                raise ValueError("invalid_msal_settings")
            read_client_secret(settings.client_secret_file)
            import msal
            import requests
            self._msal, self._requests = msal, requests
            if not identity_verifier.ready:
                return
        except (ValueError, ImportError, OSError, AttributeError):
            return
        self.settings, self.verifier, self.human_verifier = settings, identity_verifier, resource_verifier

    @property
    def ready(self):
        return self.settings is not None and self.verifier is not None and self.verifier.ready

    def authenticate_headers(self, headers):
        # No proxy assertion can create or refresh an application MSAL session.
        self.check_headers(headers)
        denied()

    def check_headers(self, headers):
        if not self.ready:
            raise AccessError(503, "authentication_unconfigured")
        reject_identity_headers(headers)

    def _new_client(self, cache_state=None):
        if not self.ready:
            raise AccessError(503, "authentication_unconfigured")
        secret = read_client_secret(self.settings.client_secret_file)
        class ManagementTokenCache(self._msal.SerializableTokenCache):
            def add(self, event, **kwargs):
                # MSAL 1.38 masks tokens but logs authorization-code event.data
                # at DEBUG. These fields are needed for redemption only, never
                # for token-cache entries or keys. Remove them before SDK logs.
                event = dict(event)
                event["data"] = {key: value for key, value in event.get("data", {}).items()
                                 if key not in ("code", "code_verifier")}
                return super().add(event, **kwargs)

        cache = ManagementTokenCache()
        if cache_state is not None:
            try:
                if (not isinstance(cache_state, str) or not 1 <= len(cache_state.encode("utf-8")) <= MAX_CACHE or
                        not isinstance(strict_json(cache_state), dict)):
                    raise ValueError()
                cache.deserialize(cache_state)
            except (AccessError, ValueError, UnicodeError):
                raise ReauthenticationRequired() from None
        options = {"client_id": self.settings.audience, "client_credential": secret,
                   "authority": self.policy.authority, "instance_discovery": False,
                   "enable_pii_log": False, "token_cache": cache}
        if self._factory is not None:
            return self._factory(**options), None
        requests, msal = self._requests, self._msal

        policy = self.policy
        class FixedSession(requests.Session):
            def request(self, method, url, **kwargs):
                parsed = urlsplit(url)
                allowed_path = ("/" + policy.tenant + "/v2.0/.well-known/openid-configuration" if method.upper() == "GET"
                                else "/" + policy.tenant + "/oauth2/v2.0/token" if method.upper() == "POST" else None)
                if (parsed.scheme != "https" or parsed.netloc != policy.host or
                        parsed.path != allowed_path or parsed.query or parsed.fragment):
                    raise AccessError(503, "authentication_unavailable")
                kwargs.update(timeout=(3.05, 10), allow_redirects=False, verify=True, stream=True)
                response = super().request(method, url, **kwargs)
                try:
                    # MSAL logs raw malformed token responses itself. Validate
                    # bounded JSON before handing a response to the SDK, so an
                    # upstream failure can never put response bytes into logs.
                    content = bytearray()
                    for chunk in response.iter_content(chunk_size=16384):
                        content.extend(chunk)
                        if len(content) > 131072:
                            raise AccessError(503, "authentication_unavailable")
                    decoded = strict_json(bytes(content))
                    if not isinstance(decoded, dict):
                        raise AccessError(503, "authentication_unavailable")
                    if method.upper() == "POST":
                        # SDK DEBUG logs refresh error_description. Strip that
                        # free text before handing any token response to MSAL.
                        decoded = sanitized_token_response(decoded)
                        content = json.dumps(decoded, separators=(",", ":")).encode("utf-8")
                    response._content, response._content_consumed = bytes(content), True
                    return response
                except AccessError:
                    raise AccessError(503, "authentication_unavailable") from None
                finally:
                    response.close()

        client_http = FixedSession()
        client_http.trust_env = False
        # Requests' default adapter has zero retries, including token POST.
        try:
            return msal.ConfidentialClientApplication(**options,
                                                      http_client=client_http), client_http
        except Exception:
            client_http.close()
            raise

    def begin(self, *, claims_challenge=None, prompt=None, previous_session_hash=None):
        if not self.ready:
            raise AccessError(503, "authentication_unconfigured")
        claims_challenge = checked_claims(claims_challenge)
        if prompt not in (None, "login"):
            raise AccessError(503, "authentication_unavailable")
        if previous_session_hash is not None and (not isinstance(previous_session_hash, str) or
                not re.fullmatch(r"[0-9a-f]{64}", previous_session_hash)):
            raise AccessError(503, "authentication_unavailable")
        now = self.monotonic()
        with self._lock:
            self._flows = {key: item for key, item in self._flows.items() if item["expires"] > now}
            if len(self._flows) + self._pending >= MAX_FLOWS:
                raise AccessError(429, "login_busy")
            self._pending += 1
        client_http = None
        try:
            client, client_http = self._new_client()
            state, cookie = secrets.token_urlsafe(36), secrets.token_urlsafe(36)
            extra = {}
            if claims_challenge is not None:
                extra["claims_challenge"] = claims_challenge
            if prompt is not None:
                extra["prompt"] = prompt
            flow = client.initiate_auth_code_flow(scopes=["email", self.settings.scope], state=state,
                                                  redirect_uri=self.policy.callback_uri, response_mode="query", **extra)
            uri = flow.get("auth_uri") if isinstance(flow, dict) else None
            if (not isinstance(uri, str) or not 1 <= len(uri) <= 32768 or
                    any(ord(char) < 33 or ord(char) > 126 for char in uri)):
                raise AccessError(503, "authentication_unavailable")
            parsed = urlsplit(uri)
            pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=32)
            fields = dict(pairs)
            nonce = flow.get("nonce") if isinstance(flow, dict) else None
            verifier = flow.get("code_verifier") if isinstance(flow, dict) else None
            if (len(fields) != len(pairs) or parsed.scheme != "https" or parsed.netloc != self.policy.host or
                    parsed.path != "/" + self.policy.tenant + "/oauth2/v2.0/authorize" or parsed.fragment or
                    flow.get("state") != state or flow.get("redirect_uri") != self.policy.callback_uri or
                    not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", nonce) or
                    not isinstance(verifier, str) or not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier) or
                    fields.get("state") != state or fields.get("redirect_uri") != self.policy.callback_uri or
                    fields.get("client_id") != self.settings.audience or fields.get("response_type") != "code" or
                    fields.get("response_mode") != "query" or fields.get("code_challenge_method") != "S256" or
                    fields.get("code_challenge") != base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii") or
                    fields.get("nonce") != hashlib.sha256(nonce.encode("ascii")).hexdigest() or
                    any(name.lower() in {"login_hint", "username", "upn", "sid"} for name in fields) or
                    fields.get("prompt") != prompt or
                    fields.get("claims") != claims_challenge or "max_age" in fields or
                    set(fields.get("scope", "").split()) != {"openid", "profile", "email", "offline_access", self.settings.scope}):
                raise AccessError(503, "authentication_unavailable")
            with self._lock:
                self._flows[state] = {"flow": flow, "cookie_hash": hashlib.sha256(cookie.encode()).hexdigest(),
                                       "expires": self.monotonic() + FLOW_SECONDS,
                                       "previous_session_hash": previous_session_hash}
            return flow["auth_uri"], cookie
        except AccessError:
            raise
        except Exception:
            raise AccessError(503, "authentication_unavailable") from None
        finally:
            if client_http is not None:
                client_http.close()
            with self._lock:
                self._pending -= 1

    def complete(self, query, cookie):
        if not self.ready:
            raise AccessError(503, "authentication_unconfigured")
        response, browser = callback_response(query), flow_cookie(cookie, self.policy.cookie_name)
        state, now = response["state"], self.monotonic()
        with self._lock:
            item = self._flows.get(state)
            if (item is None or item["expires"] <= now or
                    not hmac.compare_digest(item["cookie_hash"], hashlib.sha256(browser.encode()).hexdigest())):
                denied()
            # Consume before any network activity. Failed/parallel/replayed code
            # exchanges can never reuse this transaction.
            del self._flows[state]
        if "error" in response:
            raise AccessError(401, "login_cancelled")
        client_http, result = None, None
        try:
            client, client_http = self._new_client()
            result = client.acquire_token_by_auth_code_flow(item["flow"], response)
            self._check_result(result)
            if not isinstance(result.get("id_token"), str):
                denied()
            expected = hashlib.sha256(item["flow"]["nonce"].encode("ascii")).hexdigest()
            identity = self.verifier.authenticate([result["id_token"]], expected_nonce=expected,
                                                   require_owner_email=True)
            access = self.human_verifier.authenticate(result.get("access_token"))
            if (identity.tenant, identity.object_id) != (access.tenant, access.object_id):
                denied()
            if (identity.tenant, identity.object_id) != (self.policy.tenant, self.policy.object_id):
                raise AccessError(403, "forbidden")
            identity = replace(identity, expires_at=access.expires_at, binding=self.settings.binding,
                               authentication=self.policy.authentication, logout_url=self.policy.logout_url)
            return self._grant(client, identity, previous_session_hash=item.get("previous_session_hash"))
        except AccessError:
            raise
        except ValueError:
            # SDK protocol/state/nonce failures require a new transaction.
            raise AccessError(401, "login_failed") from None
        except Exception:
            # SDK exceptions may contain tokens, codes or nonce values.
            raise AccessError(503, "authentication_unavailable") from None
        finally:
            if isinstance(result, dict):
                result.clear()
            item["flow"].clear()
            if client_http is not None:
                client_http.close()

    @staticmethod
    def _check_result(result):
        if result is None:
            raise ReauthenticationRequired()
        if not isinstance(result, dict):
            raise AccessError(503, "authentication_unavailable")
        if "error" not in result:
            if not isinstance(result.get("access_token"), str):
                raise AccessError(503, "authentication_unavailable")
            token_type = result.get("token_type", "Bearer")
            if not isinstance(token_type, str) or token_type.lower() != "bearer":
                denied()
            return
        error = result.get("error")
        if error in ("interaction_required", "login_required", "consent_required", "invalid_grant"):
            # MSAL/Entra provides the claims challenge. Do not inspect provider
            # descriptions or turn every refresh error into prompt=login.
            raise ReauthenticationRequired(claims_challenge=result.get("claims"))
        code = "authentication_unconfigured" if error in ("invalid_client", "unauthorized_client", "invalid_scope") else "authentication_unavailable"
        raise AccessError(503, code)

    def _account(self, client, expected=None):
        accounts = client.get_accounts()
        if not isinstance(accounts, list) or len(accounts) != 1:
            raise ReauthenticationRequired()
        account = checked_account(accounts[0], self.policy)
        if expected is not None and account != checked_account(expected, self.policy):
            raise ReauthenticationRequired()
        return account

    def _grant(self, client, identity, expected=None, *, previous_session_hash=None):
        account = self._account(client, expected)
        cache_state = client.token_cache.serialize()
        if (not isinstance(cache_state, str) or not 1 <= len(cache_state.encode("utf-8")) <= MAX_CACHE or
                not isinstance(strict_json(cache_state), dict)):
            raise AccessError(503, "authentication_unavailable")
        return MsalGrant(identity, cache_state, account, previous_session_hash)

    def renew(self, cache_state, account, subject):
        """Redeem through MSAL; the caller serializes refreshes for this session.

        subject must come from the authenticated server-side session. Resource
        sub is pairwise and is never used to replace the original ID-token sub.
        """
        if not self.ready:
            raise AccessError(503, "authentication_unconfigured")
        if (not isinstance(subject, str) or not 1 <= len(subject) <= 255 or
                any(ord(char) < 33 or ord(char) > 126 for char in subject)):
            raise ReauthenticationRequired()
        account = checked_account(account, self.policy)
        client_http, result = None, None
        try:
            client, client_http = self._new_client(cache_state)
            selected = self._account(client, account)
            # The locked SDK's five-minute AT threshold decides cache vs RT.
            # No local four-hour SIF deadline, max_age or unconditional login.
            result = client.acquire_token_silent_with_error([self.settings.scope], account=selected)
            self._check_result(result)
            access = self.human_verifier.authenticate(result.get("access_token"))
            if (access.tenant, access.object_id) != (self.policy.tenant, self.policy.object_id):
                raise AccessError(403, "forbidden")
            identity = self._identity_factory(self.policy.issuer, self.settings.audience, subject, self.policy.email,
                                        access.tenant, access.object_id, access.expires_at, access.issued_at,
                                        self.settings.binding, self.settings.session_seconds,
                                        self.policy.authentication, self.policy.logout_url)
            return self._grant(client, identity, selected)
        except AccessError:
            raise
        except Exception:
            # Neither transport nor SDK exception messages are safe to expose.
            raise AccessError(503, "authentication_unavailable") from None
        finally:
            if isinstance(result, dict):
                result.clear()
            if client_http is not None:
                client_http.close()

    def cookie_header(self, value=""):
        return cookie_header(value, cookie_name=self.policy.cookie_name)
