import base64
import os
from pathlib import Path
import tempfile
import unittest

from home_net_validation import ValidationError, base64url_decode, rsa_verifier, strict_json
from home_net_validation.private_file import read_client_secret


class ValidationTests(unittest.TestCase):
    def test_json_rejects_ambiguous_nonfinite_and_unbounded_values(self):
        for raw in ('{"a":1,"a":2}', '{"nested":{"x":1,"x":2}}', 'NaN', 'Infinity', '1e999', b'"\xff"', None):
            with self.subTest(raw=repr(raw)), self.assertRaises(ValidationError):
                strict_json(raw)
        with self.assertRaises(ValidationError):
            strict_json('"long"', max_bytes=3)
        with self.assertRaises(ValidationError):
            strict_json('null', max_bytes=True)
        self.assertEqual(strict_json('{"a":[1,true,null]}'), {"a": [1, True, None]})

    def test_base64url_requires_canonical_unpadded_encoding(self):
        self.assertEqual(base64url_decode('YQ'), b'a')
        for value in ('YQ==', 'YR', 'A', '+/', '', None):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                base64url_decode(value)
        with self.assertRaises(ValidationError):
            base64url_decode('YQ', max_chars=1)

    def test_rsa_signature_and_key_strength(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = private.public_key().public_numbers()
        def encode(value):
            return base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode()
        key = {"n": encode(public.n), "e": encode(public.e)}
        signature = private.sign(b'message', padding.PKCS1v15(), hashes.SHA256())
        verify = rsa_verifier()
        verify(key, signature, b'message')
        for changed, sig, body in ((key, signature, b'changed'), (key, signature[:-1], b'message'),
                ({**key, "e": encode(2)}, signature, b'message'), ({**key, "n": encode(17)}, signature, b'message')):
            with self.assertRaises(ValidationError):
                verify(changed, sig, body)

    def test_secret_reader_rejects_permissions_links_and_nonregular_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / 'synthetic-secret'
            path.write_text('synthetic-not-a-real-client-secret\n')
            path.chmod(0o600)
            self.assertEqual(read_client_secret(str(path)), 'synthetic-not-a-real-client-secret')
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                read_client_secret(str(path))
            path.chmod(0o600)
            link = root / 'link'
            link.symlink_to(path)
            with self.assertRaises((ValueError, OSError)):
                read_client_secret(str(link))
            hard = root / 'hardlink'
            os.link(path, hard)
            with self.assertRaises(ValueError):
                read_client_secret(str(path))
            hard.unlink()
            fifo = root / 'fifo'
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(ValueError):
                read_client_secret(str(fifo))
            path.write_text('synthetic-secret\nextra-line')
            with self.assertRaises(ValueError):
                read_client_secret(str(path))


if __name__ == '__main__':
    unittest.main()
