import os

from alembic import context
from sqlalchemy import create_engine, pool

url = context.config.attributes.get("url") or os.environ.get("AEGIS_MIGRATION_DATABASE_URL")
if not url:
    raise RuntimeError("Set AEGIS_MIGRATION_DATABASE_URL to the aegis_owner connection URL")

engine = create_engine(url, poolclass=pool.NullPool)
with engine.connect() as connection:
    context.configure(connection=connection, target_metadata=None)
    with context.begin_transaction():
        context.run_migrations()
engine.dispose()
