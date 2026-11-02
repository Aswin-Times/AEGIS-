import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, and NaN or Infinity are refused."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_hash(value: Any) -> str:
    return sha256_hex(canonical_json(value))
