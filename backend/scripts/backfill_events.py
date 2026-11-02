"""Create security events for audit events written before migration 0002. Safe to rerun.

    AEGIS_MIGRATION_DATABASE_URL=<owner url> python scripts/backfill_events.py

Runs as the owner role, because listing every tenant is not something the runtime role can do.
"""

import os

from sqlalchemy import select

from aegis.db.models import Tenant
from aegis.db.session import Database
from aegis.events.backfill import backfill_tenant


def backfill_all(owner_url: str) -> int:
    database = Database(owner_url, pool_size=1, max_overflow=0)
    try:
        with database._sessions() as session:
            tenant_ids = session.execute(select(Tenant.id)).scalars().all()
        return sum(backfill_tenant(database, tenant_id) for tenant_id in tenant_ids)
    finally:
        database.dispose()


if __name__ == "__main__":
    print(f"Created {backfill_all(os.environ['AEGIS_MIGRATION_DATABASE_URL'])} security events")
