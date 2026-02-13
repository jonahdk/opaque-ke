import base64

from opaque_ke.encoding import decode_b64, encode_b64


def test_encode_decode_roundtrip():
    data = b"opaque-test-data"
    encoded = encode_b64(data)
    assert isinstance(encoded, str)
    decoded = decode_b64(encoded)
    assert decoded == data


def test_decode_b64_accepts_urlsafe_no_padding():
    data = b"opaque-urlsafe"
    encoded = base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
    decoded = decode_b64(encoded)
    assert decoded == data
