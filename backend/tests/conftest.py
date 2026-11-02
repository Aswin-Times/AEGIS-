"""Test harness: real PostgreSQL, real migrations, and the real runtime role.

The application connects as aegis_app, so RLS and grants are actually in force. A superuser
connection exists only to play an attacker who already controls the database.
"""

import os
import secrets
import shutil
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from sqlalchemy.engine import make_url

from aegis.db.bootstrap import ensure_roles_and_database, run_migrations
from aegis.db.session import Database
from aegis.provisioning import provision_tenant


@pytest.fixture(scope="session")
def admin_url() -> Iterator[str]:
    configured = os.environ.get("AEGIS_TEST_ADMIN_URL")
    if configured:
        yield configured
        return
    import pgserver

    directory = tempfile.mkdtemp(prefix="aegis-test-pg-")
    server = pgserver.get_server(directory, cleanup_mode="delete")
    try:
        yield server.get_uri()
    finally:
        server.cleanup()
        shutil.rmtree(directory, ignore_errors=True)


@dataclass(frozen=True)
class DatabaseUrls:
    owner: str
    app: str
    superuser: str


@pytest.fixture(scope="session")
def urls(admin_url: str) -> Iterator[DatabaseUrls]:
    name = f"aegis_test_{uuid4().hex}"
    owner, app = ensure_roles_and_database(
        admin_url,
        database=name,
        owner_password=secrets.token_urlsafe(16),
        app_password=secrets.token_urlsafe(16),
    )
    run_migrations(owner)
    superuser = (
        make_url(admin_url)
        .set(drivername="postgresql", database=name)
        .render_as_string(hide_password=False)
    )
    yield DatabaseUrls(owner=owner, app=app, superuser=superuser)
    with psycopg.connect(admin_url, autocommit=True) as connection:
        connection.execute(f'DROP DATABASE "{name}" WITH (FORCE)')


@pytest.fixture(scope="session")
def db(urls: DatabaseUrls) -> Iterator[Database]:
    database = Database(urls.app)
    yield database
    database.dispose()


@pytest.fixture
def attacker_sql(urls: DatabaseUrls) -> Iterator[psycopg.Connection]:
    """Superuser access, standing in for a full database compromise."""
    with psycopg.connect(urls.superuser, autocommit=True) as connection:
        yield connection


@pytest.fixture
def new_tenant(urls: DatabaseUrls):
    def create() -> UUID:
        slug = f"t-{uuid4().hex[:16]}"
        return provision_tenant(urls.owner, slug=slug, name=f"Synthetic {slug}")

    return create


@pytest.fixture(scope="session")
def jwt_key_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("keys") / "jwt.pem"
    path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
    )
    return path
