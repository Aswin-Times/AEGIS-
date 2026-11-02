"""Run the API locally for development, against embedded PostgreSQL by default.

Set AEGIS_ADMIN_DATABASE_URL to use an existing server instead, as Docker Compose does.

    python scripts/dev_stack.py

State lives in backend/.dev, which git ignores. Delete that directory to start clean. The
first run seeds a synthetic demo tenant through the real API, and writes its generated login
to backend/.dev/demo-credentials.json.
"""

import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from seed_demo import seed

from aegis.db.bootstrap import ensure_roles_and_database, run_migrations

BACKEND = Path(__file__).resolve().parents[1]
DEV = BACKEND / ".dev"
PORT = int(os.environ.get("AEGIS_API_PORT", "8000"))
HOST = os.environ.get("AEGIS_API_HOST", "127.0.0.1")


def _load_or_create_passwords() -> dict[str, str]:
    path = DEV / "db-passwords.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    values = {"owner": secrets.token_urlsafe(24), "app": secrets.token_urlsafe(24)}
    path.write_text(json.dumps(values), encoding="utf-8")
    return values


def _ensure_jwt_key() -> Path:
    path = DEV / "jwt-ed25519.pem"
    if not path.exists():
        path.write_bytes(
            Ed25519PrivateKey.generate().private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
        )
    return path


def _wait_until_healthy(url: str) -> None:
    for _ in range(100):
        try:
            with urllib.request.urlopen(f"{url}/healthz", timeout=1) as response:  # noqa: S310
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("The API did not become healthy")


def main() -> int:
    DEV.mkdir(exist_ok=True)
    passwords = _load_or_create_passwords()
    server = None
    admin_url = os.environ.get("AEGIS_ADMIN_DATABASE_URL")
    if admin_url is None:
        import pgserver

        server = pgserver.get_server(DEV / "pgdata", cleanup_mode="stop")
        admin_url = server.get_uri()
    owner_url, app_url = ensure_roles_and_database(
        admin_url,
        database="aegis",
        owner_password=passwords["owner"],
        app_password=passwords["app"],
    )
    run_migrations(owner_url)

    environment = {
        **os.environ,
        "AEGIS_ENVIRONMENT": "development",
        "AEGIS_DATABASE_URL": app_url,
        "AEGIS_JWT_PRIVATE_KEY_PATH": str(_ensure_jwt_key()),
    }
    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "aegis.api.asgi:app", "--host", HOST,
         "--port", str(PORT)],
        cwd=BACKEND,
        env=environment,
    )
    try:
        base_url = f"http://127.0.0.1:{PORT}"
        _wait_until_healthy(base_url)
        credentials = DEV / "demo-credentials.json"
        if not credentials.exists():
            seed(base_url, owner_url, credentials)
        print(f"AEGIS API ready at {base_url}. Demo login: {credentials}", flush=True)
        return api.wait()
    finally:
        api.terminate()
        if server is not None:
            server.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
