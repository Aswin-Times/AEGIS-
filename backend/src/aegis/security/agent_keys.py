import hashlib
import hmac
import secrets
from dataclasses import dataclass
from uuid import UUID

PREFIX = "aegis_agent"


@dataclass(frozen=True)
class ParsedAgentKey:
    tenant_id: UUID
    credential_id: UUID
    secret: str


def generate_secret() -> str:
    return secrets.token_urlsafe(32)


def hash_secret(secret: str) -> bytes:
    # The secret is 256 bits of randomness, so a slow hash adds cost and no protection.
    return hashlib.sha256(secret.encode("utf-8")).digest()


def secret_matches(secret: str, stored_hash: bytes | None) -> bool:
    return hmac.compare_digest(hash_secret(secret), stored_hash or b"\0" * 32)


def format_key(tenant_id: UUID, credential_id: UUID, secret: str) -> str:
    return f"{PREFIX}.{tenant_id}.{credential_id}.{secret}"


def parse_key(key: str) -> ParsedAgentKey | None:
    parts = key.split(".")
    if len(parts) != 4 or parts[0] != PREFIX or not parts[3]:
        return None
    try:
        return ParsedAgentKey(UUID(parts[1]), UUID(parts[2]), parts[3])
    except ValueError:
        return None
