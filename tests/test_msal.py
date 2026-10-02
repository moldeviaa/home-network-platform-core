"""Offline orchestration tests; injected verifiers here are synthetic test doubles."""
import base64
from dataclasses import dataclass, replace
import hashlib
from http.client import HTTPMessage
from pathlib import Path
import secrets
import tempfile
from types import SimpleNamespace
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit
from unittest.mock import patch

from home_net_auth import AuthError, FlowPolicy, MsalAuth, ReauthenticationRequired
from home_net_auth.msal import MAX_FLOWS, callback_response, checked_claims, cookie_header, sanitized_token_response

TENANT = '00000000-0000-4000-8000-000000000001'
OBJECT = '00000000-0000-4000-8000-000000000002'
CLIENT = '00000000-0000-4000-8000-000000000003'
RESOURCE = '00000000-0000-4000-8000-000000000004'


@dataclass(frozen=True)
class Identity:
    issuer: str
    audience: str
    subject: str
    email: str
    tenant: str
    object_id: str
    expires_at: int
    issued_at: int
    binding: str
    session_seconds: int
    authentication: str = 'test'
    logout_url: str = '/signed-out'


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path = Path(self.temp.name).resolve() / 'synthetic-secret'
        path.write_text('synthetic-not-a-real-client-secret')
        path.chmod(0o600)
        self.policy = FlowPolicy(TENANT, OBJECT, 'operator@example.invalid', 'https://manage.example.invalid',
                                 '__Host-example_login', 'entra_msal', '/signed-out')
        self.settings = SimpleNamespace(audience=CLIENT, session_seconds=3600, client_secret_file=str(path),
                                        scope='api://' + RESOURCE + '/Example.Access', binding='a' * 64)
        self.now, self.mono, self.exchanges, self.silent, self.change = 1800000000, 1, 0, 0, {}
        self.response = {"access_token": "synthetic-access", "id_token": "synthetic-id", "token_type": "Bearer"}
        identity = Identity(self.policy.issuer, CLIENT, 'synthetic-subject', self.policy.email, TENANT, OBJECT,
                            self.now + 1800, self.now, 'b' * 64, 3600)
        self.identity = SimpleNamespace(ready=True, authenticate=lambda tokens, **kw: identity)
        self.resource = SimpleNamespace(authenticate=lambda token: identity)
        self.auth = self.make_auth()

    def make_auth(self, **changes):
        options = dict(identity_verifier=self.identity, resource_verifier=self.resource,
                       identity_factory=Identity, factory=self.factory, clock=lambda: self.now, monotonic=lambda: self.mono)
        options.update(changes)
        return MsalAuth(self.settings, self.policy, **options)

    def factory(self, **options):
        outer = self
        class Client:
            token_cache = SimpleNamespace(serialize=lambda: '{"synthetic":true}')
            def get_accounts(self):
                return [{"home_account_id": OBJECT + '.' + TENANT, "environment": outer.policy.host,
                         "realm": TENANT, "local_account_id": OBJECT}]
            def initiate_auth_code_flow(self, **kwargs):
                nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(36)
                fields = {"client_id": CLIENT, "state": kwargs['state'], "redirect_uri": outer.policy.callback_uri,
                          "response_type": "code", "response_mode": "query", "scope": 'openid profile email offline_access ' + outer.settings.scope,
                          "nonce": hashlib.sha256(nonce.encode()).hexdigest(), "code_challenge_method": "S256",
                          "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()}
                fields.update(outer.change)
                return {"state": kwargs['state'], "redirect_uri": outer.policy.callback_uri, "nonce": nonce,
                        "code_verifier": verifier, "auth_uri": outer.policy.authority + '/oauth2/v2.0/authorize?' + urlencode(fields)}
            def acquire_token_by_auth_code_flow(self, flow, response):
                outer.exchanges += 1
                return dict(outer.response)
            def acquire_token_silent_with_error(self, scopes, *, account):
                outer.silent += 1
                return dict(outer.response)
        return Client()

    def begin(self):
        uri, cookie = self.auth.begin()
        return parse_qs(urlsplit(uri).query)['state'][0], self.policy.cookie_name + '=' + cookie

    def test_no_verifier_no_readiness_network_and_no_ambient_identity(self):
        with self.assertRaises(ValueError):
            self.make_auth(identity_verifier=None)
        with patch('requests.Session.request', side_effect=AssertionError('readiness network')):
            self.assertTrue(self.make_auth().ready)
        headers = HTTPMessage()
        headers.add_header('X-Forwarded-User', 'synthetic')
        with self.assertRaises(AuthError):
            self.auth.check_headers(headers)
        self.settings.audience = 'invalid'
        self.assertFalse(self.make_auth().ready)

    def test_single_use_state_cookie_and_failed_exchange_consumption(self):
        state, cookie = self.begin()
        query = urlencode({"state": state, "code": "synthetic"})
        with self.assertRaises(AuthError):
            self.auth.complete(query, self.policy.cookie_name + '=' + 'b' * 48)
        grant = self.auth.complete(query, cookie)
        self.assertEqual(grant.identity.authentication, 'entra_msal')
        self.assertNotIn('synthetic-access', repr(grant))
        with self.assertRaises(AuthError):
            self.auth.complete(query, cookie)
        self.assertEqual(self.exchanges, 1)
        state, cookie = self.begin()
        self.response = {"error": "temporarily_unavailable", "error_description": "synthetic-private-description"}
        query = urlencode({"state": state, "code": "synthetic"})
        with self.assertRaises(AuthError):
            self.auth.complete(query, cookie)
        with self.assertRaises(AuthError):
            self.auth.complete(query, cookie)
        self.assertEqual(self.exchanges, 2)

    def test_flow_deadline_capacity_and_pkce_destination(self):
        state, cookie = self.begin()
        self.mono += 301
        with self.assertRaises(AuthError):
            self.auth.complete(urlencode({"state": state, "code": "synthetic"}), cookie)
        for _ in range(MAX_FLOWS):
            self.begin()
        with self.assertRaises(AuthError) as error:
            self.begin()
        self.assertEqual(error.exception.code, 'login_busy')
        self.mono += 301
        self.change['redirect_uri'] = 'https://evil.example.invalid'
        with self.assertRaises(AuthError):
            self.begin()
        self.assertEqual(self.exchanges, 0)

    def test_resource_identity_is_independently_checked(self):
        state, cookie = self.begin()
        self.resource.authenticate = lambda token: SimpleNamespace(tenant=TENANT, object_id=CLIENT)
        with self.assertRaises(AuthError):
            self.auth.complete(urlencode({"state": state, "code": "synthetic"}), cookie)

    def test_matching_verifiers_cannot_return_a_different_policy_operator(self):
        foreign = Identity(self.policy.issuer, CLIENT, 'subject', self.policy.email, TENANT, CLIENT,
                           self.now + 1800, self.now, 'b' * 64, 3600)
        self.identity.authenticate = lambda tokens, **kw: foreign
        self.resource.authenticate = lambda token: foreign
        state, cookie = self.begin()
        with self.assertRaises(AuthError) as error:
            self.auth.complete(urlencode({"state": state, "code": "synthetic"}), cookie)
        self.assertEqual(error.exception.status, 403)

    def test_silent_renewal_uses_bound_account_and_classifies_provider_errors(self):
        state, cookie = self.begin()
        grant = self.auth.complete(urlencode({"state": state, "code": "synthetic"}), cookie)
        refreshed = self.auth.renew(grant.cache_state, grant.account, grant.identity.subject)
        self.assertEqual(refreshed.identity.subject, grant.identity.subject)
        self.assertEqual(self.silent, 1)
        with self.assertRaises(ReauthenticationRequired):
            self.auth.renew(grant.cache_state, {**grant.account, 'realm': CLIENT}, grant.identity.subject)
        self.response = {"error": "interaction_required", "claims": '{"access_token":{"test":{}}}',
                         "error_description": "synthetic-private-description"}
        with self.assertRaises(ReauthenticationRequired) as error:
            self.auth.renew(grant.cache_state, grant.account, grant.identity.subject)
        self.assertNotIn('description', str(error.exception))

    def test_protocol_inputs_and_cookie_reject_ambiguity_and_injection(self):
        state = 'a' * 48
        for query in ('state=' + state + '&state=' + state + '&code=x', 'state=' + state + '&code=x&error=x'):
            with self.assertRaises(AuthError):
                callback_response(query)
        with self.assertRaises(ValueError):
            cookie_header('x\r\nSet-Cookie: injected', cookie_name=self.policy.cookie_name)
        with self.assertRaises(AuthError):
            checked_claims('{"access_token":{},"access_token":{}}')
        clean = sanitized_token_response({"error": "invalid_grant", "error_description": "synthetic-private-description",
                                          "unexpected": "synthetic", "claims": '{"access_token":{}}'})
        self.assertEqual(set(clean), {'error', 'claims'})

    def test_policy_rejects_unsafe_origins_and_cookies(self):
        for values in ({'public_origin': 'http://manage.example.invalid'}, {'public_origin': 'https://u:p@example.invalid'},
                       {'tenant': 'common'}, {'cookie_name': 'example'}, {'host': 'evil.example.invalid'}):
            with self.assertRaises(ValueError):
                replace(self.policy, **values)


if __name__ == '__main__':
    unittest.main()
