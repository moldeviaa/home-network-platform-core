"""Authentication decisions contain no provider text or token material."""
import re


class AuthError(Exception):
    def __init__(self, status=401, code="unauthorized"):
        if type(status) is not int or not 400 <= status <= 599 or not isinstance(code, str) or not re.fullmatch(r"[a-z_]{1,64}", code):
            raise ValueError("invalid_auth_error")
        self.status, self.code = status, code
        super().__init__(code)


def denied():
    raise AuthError()
