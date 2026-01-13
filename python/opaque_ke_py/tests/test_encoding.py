from opaque_ke.encoding import decode_b64, encode_b64


def test_encode_decode_roundtrip():
    data = b"opaque-test-data"
    encoded = encode_b64(data)
    assert isinstance(encoded, str)
    decoded = decode_b64(encoded)
    assert decoded == data
