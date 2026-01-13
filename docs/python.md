# Python bindings

The `opaque-ke` Python bindings expose a high-level API (`OpaqueClient`/`OpaqueServer`)
plus lower-level functions that mirror the JS SDK naming. The bindings currently target
`ristretto255_sha512`.

## Install (local dev)

```
.venv/bin/python -m pip install -U pip
cd python/opaque_ke_py
.venv/bin/python -m maturin develop
```

## High-level API

```python
from opaque_ke.client import OpaqueClient
from opaque_ke.server import OpaqueServer
from opaque_ke.types import ServerSetup

client = OpaqueClient()
server = OpaqueServer()
server_setup = ServerSetup()

password = b"password"
credential_identifier = b"user@example.com"

# Registration
req, reg_state = client.start_registration(password)
resp = server.start_registration(server_setup, req, credential_identifier)
upload, export_key = client.finish_registration(reg_state, password, resp, None)
password_file = server.finish_registration(upload)

# Login
req, login_state = client.start_login(password)
resp, server_state = server.start_login(
    server_setup, password_file, req, credential_identifier, None
)
finalization, session_key, export_key, server_s_pk = client.finish_login(
    login_state, password, resp, None
)
server_session_key = server.finish_login(server_state, finalization, None)

assert session_key == server_session_key
```

## Low-level API

```python
from opaque_ke import registration, login
from opaque_ke.types import ServerSetup

server_setup = ServerSetup()
password = b"password"
credential_identifier = b"user@example.com"

req, reg_state = registration.client.start_registration(password)
resp = registration.server.start_registration(server_setup, req, credential_identifier)
upload, _ = registration.client.finish_registration(reg_state, password, resp, None)
password_file = registration.server.finish_registration(upload)

req, login_state = login.client.start_login(password)
resp, server_state = login.server.start_login(
    server_setup, password_file, req, credential_identifier, None
)
finalization, session_key, _, _ = login.client.finish_login(
    login_state, password, resp, None
)
server_session_key = login.server.finish_login(server_state, finalization, None)

assert session_key == server_session_key
```

## Parameters, identifiers, and context

Use the parameter objects in `opaque_ke.types` when you need identifiers, context,
key stretching, or server public key pinning:

```python
from opaque_ke.types import (
    Identifiers,
    ClientRegistrationFinishParameters,
    ServerLoginParameters,
    ClientLoginFinishParameters,
)

identifiers = Identifiers(client=b"client", server=b"server")
reg_params = ClientRegistrationFinishParameters(identifiers, None)

context = b"opaque-python"
server_params = ServerLoginParameters(context, identifiers)
client_params = ClientLoginFinishParameters(context, identifiers, None, None)
```

## Encoding helpers

Protocol messages are bytes. Use base64 helpers for storage/transport:

```python
from opaque_ke.encoding import encode_b64, decode_b64

encoded = encode_b64(b"payload")
assert decode_b64(encoded) == b"payload"
```

## State handling

State objects are single-use. Reusing a state will raise `InvalidStateError`.
To persist across processes, serialize to bytes and store with base64.

## Error mapping

Errors map to `opaque_ke.errors`:

- `OpaqueError` (base class)
- `InvalidLoginError`
- `InvalidStateError`
- `SerializationError`
- `SizeError`
- `ReflectedValueError`
- `LibraryError`

## Testing

```
cd python/opaque_ke_py
.venv/bin/python -m pytest
```

### JS interop tests

Interop tests are gated behind `OPAQUE_JS_INTEROP=1` and run against
`@serenity-kit/opaque` using the repo-local JS harness in
`python/opaque_ke_py/tests/js/`.

```
cd python/opaque_ke_py/tests/js
npm install

cd ../../..
OPAQUE_JS_INTEROP=1 .venv/bin/python -m pytest python/opaque_ke_py/tests/test_js_interop.py
```
