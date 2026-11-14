"""Create a synthetic tenant with the users the approval e2e tests need, apart from the demo tenant.

Approval tests need two admins (neither can grant the governance role to themselves), reviewers
with and without the grant, and a viewer. A tenant of their own keeps the demo tenant as it was
found. Usage: provision_governance_tenant.py <slug> <password>
"""

import json
import sys
from pathlib import Path

from aegis.provisioning import create_user, provision_tenant

DEV = Path(__file__).resolve().parents[2] / "backend" / ".dev"

USERS = (
    ("admin", "admin"),
    ("admin2", "admin"),
    ("reviewer", "reviewer"),
    ("reviewer2", "reviewer"),
    ("viewer", "viewer"),
)


def main(slug: str, password: str) -> None:
    passwords = json.loads((DEV / "db-passwords.json").read_text(encoding="utf-8"))
    port = (DEV / "pgdata" / "postmaster.pid").read_text(encoding="utf-8").splitlines()[3]
    owner_url = (
        f"postgresql+psycopg://aegis_owner:{passwords['owner']}@127.0.0.1:{port}/aegis"
    )
    tenant_id = provision_tenant(owner_url, slug=slug, name="Synthetic Approval Organization")
    for name, role in USERS:
        create_user(
            owner_url, tenant_id, email=f"{name}@synthetic.example.test", password=password,
            role=role,
        )


if __name__ == "__main__":
    # Failures can carry the owner URL, which holds the database password, so report only the type.
    try:
        main(*sys.argv[1:3])
    except Exception as error:
        print(f"provision_governance_tenant failed: {type(error).__name__}", file=sys.stderr)
        sys.exit(1)
