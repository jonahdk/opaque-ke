import importlib

import pytest

opaque_ke = pytest.importorskip(
    "opaque_ke",
    reason="opaque_ke extension not built; run 'maturin develop' in python/opaque_ke_py",
)

try:
    importlib.import_module("opaque_ke.client")
    importlib.import_module("opaque_ke.server")
    importlib.import_module("opaque_ke.types")
except ModuleNotFoundError as exc:
    if exc.name and exc.name.startswith("opaque_ke"):
        pytest.skip(
            "opaque_ke extension not built; run 'maturin develop' in python/opaque_ke_py",
            allow_module_level=True,
        )
    raise

from opaque_ke.client import OpaqueClient
from opaque_ke.server import OpaqueServer
from opaque_ke.types import ServerSetup


@pytest.fixture
def client():
    return OpaqueClient()


@pytest.fixture
def server():
    return OpaqueServer()


@pytest.fixture
def server_setup():
    return ServerSetup()


@pytest.fixture
def password():
    return b"password123"


@pytest.fixture
def credential_identifier():
    return b"user@example.com"
