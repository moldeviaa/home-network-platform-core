"""Bounded input and cryptographic primitives; no site defaults or network IO."""
import base64
import json
import math
import re


class ValidationError(ValueError):
    """A fixed diagnostic code, never the rejected input."""


def strict_json(raw, *, max_bytes=1048576):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValidationError("duplicate_json_field")
            value[key] = item
        return value

    def constant(_value):
        raise ValidationError("nonfinite_json_number")

    def number(raw):
        value = float(raw)
        if not math.isfinite(value):
            raise ValidationError("nonfinite_json_number")
        return value

    try:
        if type(max_bytes) is not int or not 1 <= max_bytes <= 16777216:
            raise ValidationError("invalid_json_limit")
        if not isinstance(raw, (str, bytes)):
            raise ValidationError("invalid_json_type")
        data = raw.encode("utf-8") if isinstance(raw, str) else raw
        if len(data) > max_bytes:
            raise ValidationError("json_too_large")
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant, parse_float=number)
    except ValidationError:
        raise
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise ValidationError("invalid_json") from None


def base64url_decode(value, *, max_chars=1048576):
    if (type(max_chars) is not int or not 1 <= max_chars <= 16777216 or
            not isinstance(value, str) or not 1 <= len(value) <= max_chars or
            not re.fullmatch(r"[A-Za-z0-9_-]+", value)):
        raise ValidationError("invalid_base64url")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
            raise ValidationError("noncanonical_base64url")
        return raw
    except (ValueError, UnicodeError):
        raise ValidationError("invalid_base64url") from None


def rsa_verifier():
    """RS256 primitive only: callers must validate issuer, claims and key selection."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    def verify(key, signature, message):
        try:
            if not isinstance(key, dict) or not isinstance(signature, bytes) or not isinstance(message, bytes):
                raise ValidationError("invalid_rsa_input")
            n = int.from_bytes(base64url_decode(key.get("n"), max_chars=2048), "big")
            e = int.from_bytes(base64url_decode(key.get("e"), max_chars=16), "big")
            if (not 2048 <= n.bit_length() <= 8192 or not 3 <= e <= 0xffffffff or e % 2 == 0 or
                    len(signature) != (n.bit_length() + 7) // 8 or len(message) > 1048576):
                raise ValidationError("invalid_rsa_input")
            rsa.RSAPublicNumbers(e, n).public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        except Exception:
            raise ValidationError("invalid_rsa_signature") from None
    return verify
