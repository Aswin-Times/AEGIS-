from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from aegis.config import Settings
from aegis.errors import Unauthenticated

ALGORITHM = "EdDSA"


@dataclass(frozen=True)
class TokenClaims:
    user_id: UUID
    tenant_id: UUID


class TokenService:
    def __init__(self, settings: Settings) -> None:
        key = load_pem_private_key(settings.jwt_private_key_path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("The JWT signing key must be Ed25519")
        self._private_key = key
        self._public_key = key.public_key()
        self._issuer = settings.jwt_issuer
        self._audience = settings.jwt_audience
        self.ttl_seconds = settings.access_token_ttl_seconds

    def issue(self, *, user_id: UUID, tenant_id: UUID, now: datetime | None = None) -> str:
        issued_at = now or datetime.now(UTC)
        return jwt.encode(
            {
                "iss": self._issuer,
                "aud": self._audience,
                "sub": str(user_id),
                "tid": str(tenant_id),
                "iat": issued_at,
                "exp": issued_at + timedelta(seconds=self.ttl_seconds),
                "jti": str(uuid4()),
            },
            self._private_key,
            algorithm=ALGORITHM,
        )

    def verify(self, token: str) -> TokenClaims:
        try:
            claims = jwt.decode(
                token,
                self._public_key,
                algorithms=[ALGORITHM],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "jti", "tid"]},
            )
            return TokenClaims(user_id=UUID(claims["sub"]), tenant_id=UUID(claims["tid"]))
        except (jwt.InvalidTokenError, ValueError, TypeError) as error:
            raise Unauthenticated() from error
