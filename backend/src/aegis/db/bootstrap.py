"""Database setup that needs elevated rights: roles, the database, and migrations.

Only setup tooling and tests use this module. The running API never does.
"""

from pathlib import Path

import psycopg
from alembic import command
from alembic.config import Config
from psycopg import sql
from sqlalchemy.engine import make_url

BACKEND_ROOT = Path(__file__).resolve().parents[3]


def _with_database(url: str, *, username: str, password: str, database: str) -> str:
    """Return a SQLAlchemy psycopg URL for the same server with other credentials."""
    parsed = make_url(url).set(
        drivername="postgresql+psycopg", username=username, password=password, database=database
    )
    return parsed.render_as_string(hide_password=False)


def _libpq(url: str) -> str:
    return make_url(url).set(drivername="postgresql").render_as_string(hide_password=False)


def ensure_roles_and_database(
    admin_url: str, *, database: str, owner_password: str, app_password: str
) -> tuple[str, str]:
    """Create the roles and database if needed. Returns (owner_url, app_url)."""
    with psycopg.connect(_libpq(admin_url), autocommit=True) as connection:
        for role, password in (("aegis_owner", owner_password), ("aegis_app", app_password)):
            exists = connection.execute(
                "SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)
            ).fetchone()
            verb = sql.SQL("ALTER" if exists else "CREATE")
            connection.execute(
                sql.SQL(
                    "{} ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD {}"
                ).format(verb, sql.Identifier(role), sql.Literal(password))
            )
        exists = connection.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s", (database,)
        ).fetchone()
        if not exists:
            connection.execute(
                sql.SQL("CREATE DATABASE {} OWNER aegis_owner").format(sql.Identifier(database))
            )
    return (
        _with_database(admin_url, username="aegis_owner", password=owner_password,
                       database=database),
        _with_database(admin_url, username="aegis_app", password=app_password,
                       database=database),
    )


def run_migrations(owner_url: str) -> None:
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "migrations"))
    config.attributes["url"] = owner_url
    command.upgrade(config, "head")
