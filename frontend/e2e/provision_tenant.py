"""Create an empty synthetic tenant with one admin, for tests that need a tenant with no assets.

Tenants have no API, so this uses the same provisioning code as the demo seed, against the dev
stack's database. Usage: provision_tenant.py <slug> <email> <password>
"""

import json
import sys
from pathlib import Path

from aegis.provisioning import create_user, provision_tenant

DEV = Path(__file__).resolve().parents[2] / "backend" / ".dev"


def main(slug: str, email: str, password: str) -> None:
    passwords = json.loads((DEV / "db-passwords.json").read_text(encoding="utf-8"))
    port = (DEV / "pgdata" / "postmaster.pid").read_text(encoding="utf-8").splitlines()[3]
    owner_url = (
        f"postgresql+psycopg://aegis_owner:{passwords['owner']}@127.0.0.1:{port}/aegis"
    )
    tenant_id = provision_tenant(owner_url, slug=slug, name="Synthetic Empty Organization")
    create_user(owner_url, tenant_id, email=email, password=password, role="admin")


if __name__ == "__main__":
    # Failures can carry the owner URL, which holds the database password, so report only the type.
    try:
        main(*sys.argv[1:4])
    except Exception as error:
        print(f"provision_tenant failed: {type(error).__name__}", file=sys.stderr)
        sys.exit(1)
