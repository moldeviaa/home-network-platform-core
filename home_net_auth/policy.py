"""Explicit per-application policy, with no default tenant, user or origin."""
from dataclasses import dataclass
import re
from urllib.parse import urlsplit

UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


def valid_client_id(value):
    return bool(isinstance(value, str) and UUID.fullmatch(value) and value != "00000000-0000-0000-0000-000000000000")


@dataclass(frozen=True)
class FlowPolicy:
    tenant: str
    object_id: str
    email: str
    public_origin: str
    cookie_name: str
    authentication: str
    logout_url: str
    callback_path: str = "/oauth2/callback"
    host: str = "login.microsoftonline.com"

    def __post_init__(self):
        try:
            if not isinstance(self.public_origin, str):
                raise ValueError()
            origin = urlsplit(self.public_origin)
            if origin.port is not None and not 1 <= origin.port <= 65535:
                raise ValueError()
        except (ValueError, TypeError):
            raise ValueError("invalid_flow_policy") from None
        if (not valid_client_id(self.tenant) or not valid_client_id(self.object_id) or
                not isinstance(self.email, str) or not re.fullmatch(r"[^\s@]{1,128}@[^\s@]{1,128}", self.email) or
                self.host not in {"login.microsoftonline.com", "login.microsoftonline.us", "login.chinacloudapi.cn"} or
                origin.scheme != "https" or not origin.hostname or origin.username or origin.password or
                origin.path or origin.query or origin.fragment or origin.netloc != origin.netloc.lower() or
                not re.fullmatch(r"https://[a-z0-9.-]+(?::[0-9]{1,5})?", self.public_origin) or
                not isinstance(self.cookie_name, str) or not re.fullmatch(r"__Host-[A-Za-z0-9_-]{1,64}", self.cookie_name) or
                not isinstance(self.authentication, str) or not re.fullmatch(r"[a-z_]{1,64}", self.authentication) or
                any(not isinstance(path, str) or not re.fullmatch(r"/[A-Za-z0-9/_-]{1,128}", path) or "//" in path
                    for path in (self.callback_path, self.logout_url))):
            raise ValueError("invalid_flow_policy")

    @property
    def authority(self):
        return "https://" + self.host + "/" + self.tenant

    @property
    def issuer(self):
        return self.authority + "/v2.0"

    @property
    def callback_uri(self):
        return self.public_origin + self.callback_path
