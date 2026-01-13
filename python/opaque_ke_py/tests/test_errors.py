import pytest

from opaque_ke.client import OpaqueClient
from opaque_ke.errors import InvalidLoginError, InvalidStateError, SerializationError
from opaque_ke.server import OpaqueServer
from opaque_ke.types import ServerSetup


def test_invalid_login_wrong_password():
    client = OpaqueClient()
    server = OpaqueServer()
    server_setup = ServerSetup()
    password = b"correct-password"
    credential_identifier = b"user"

    req, reg_state = client.start_registration(password)
    resp = server.start_registration(server_setup, req, credential_identifier)
    upload, _ = client.finish_registration(reg_state, password, resp, None)
    password_file = server.finish_registration(upload)

    req, login_state = client.start_login(b"wrong-password")
    resp, server_state = server.start_login(
        server_setup, password_file, req, credential_identifier, None
    )

    with pytest.raises(InvalidLoginError):
        client.finish_login(login_state, b"wrong-password", resp, None)

    # Server state is intentionally left unused; it should be dropped safely.
    del server_state


def test_state_reuse_raises_invalid_state():
    client = OpaqueClient()
    server = OpaqueServer()
    server_setup = ServerSetup()
    password = b"password"
    credential_identifier = b"user"

    req, reg_state = client.start_registration(password)
    resp = server.start_registration(server_setup, req, credential_identifier)

    client.finish_registration(reg_state, password, resp, None)

    with pytest.raises(InvalidStateError):
        client.finish_registration(reg_state, password, resp, None)


def test_serialization_error_helpers():
    from opaque_ke.encoding import decode_b64

    with pytest.raises(SerializationError):
        decode_b64("not-base64!")
