"""Versioned correlation rules. Defaults come from code. Changes create immutable versions."""

import json
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from aegis.audit.chain import append_event
from aegis.canonical import canonical_json, sha256_hex
from aegis.correlation.rules import DEFAULT_RULES, CorrelationRule
from aegis.db.models import CorrelationRuleVersion
from aegis.errors import NotFound
from aegis.security.principals import UserPrincipal


class RuleIntegrityError(Exception):
    """A stored rule failed its hash or validation, so detection cannot be trusted."""


@dataclass(frozen=True)
class LoadedRule:
    version: CorrelationRuleVersion
    rule: CorrelationRule


def _canonical(rule: CorrelationRule) -> str:
    return canonical_json(rule.model_dump(mode="json", exclude_none=True))


def _ensure_defaults(session: Session, tenant_id: UUID, now: datetime) -> None:
    existing = set(
        session.execute(select(CorrelationRuleVersion.rule_key).distinct()).scalars()
    )
    for key, rule in DEFAULT_RULES.items():
        if key in existing:
            continue
        canonical = _canonical(rule)
        inserted = session.execute(
            insert(CorrelationRuleVersion)
            .values(
                id=uuid4(),
                tenant_id=tenant_id,
                rule_key=key,
                version=1,
                definition_canonical=canonical,
                content_hash=sha256_hex(canonical),
            )
            .on_conflict_do_nothing()
            .returning(CorrelationRuleVersion.id)
        ).first()
        if inserted is not None:
            append_event(
                session,
                tenant_id,
                event_type="correlation.rule_seeded",
                actor_type="system",
                subject_type="correlation_rule_version",
                subject_id=inserted[0],
                occurred_at=now,
                payload={"rule_key": key, "version": 1},
            )


def parse_version(version: CorrelationRuleVersion) -> CorrelationRule:
    if sha256_hex(version.definition_canonical) != version.content_hash:
        raise RuleIntegrityError(f"{version.rule_key} v{version.version} failed its hash")
    try:
        return CorrelationRule.model_validate(json.loads(version.definition_canonical))
    except (ValidationError, ValueError) as error:
        raise RuleIntegrityError(f"{version.rule_key} v{version.version} is invalid") from error


def load_rules(session: Session, tenant_id: UUID, now: datetime) -> list[LoadedRule]:
    """The newest version of each rule, in a stable order. Raises if any cannot be trusted."""
    _ensure_defaults(session, tenant_id, now)
    newest = (
        select(
            CorrelationRuleVersion.rule_key,
            func.max(CorrelationRuleVersion.version).label("version"),
        )
        .group_by(CorrelationRuleVersion.rule_key)
        .subquery()
    )
    versions = session.execute(
        select(CorrelationRuleVersion)
        .join(
            newest,
            (newest.c.rule_key == CorrelationRuleVersion.rule_key)
            & (newest.c.version == CorrelationRuleVersion.version),
        )
        .order_by(CorrelationRuleVersion.rule_key)
    ).scalars()
    return [LoadedRule(version, parse_version(version)) for version in versions]


def create_rule_version(
    session: Session,
    user: UserPrincipal,
    rule_key: str,
    rule: CorrelationRule,
    now: datetime,
) -> CorrelationRuleVersion:
    if rule_key not in DEFAULT_RULES:
        raise NotFound()
    _ensure_defaults(session, user.tenant_id, now)
    latest = session.execute(
        select(func.max(CorrelationRuleVersion.version)).where(
            CorrelationRuleVersion.rule_key == rule_key
        )
    ).scalar_one()
    canonical = _canonical(rule)
    version = CorrelationRuleVersion(
        id=uuid4(),
        tenant_id=user.tenant_id,
        rule_key=rule_key,
        version=latest + 1,
        definition_canonical=canonical,
        content_hash=sha256_hex(canonical),
        created_by=user.id,
    )
    session.add(version)
    session.flush()
    append_event(
        session,
        user.tenant_id,
        event_type="correlation.rule_version_created",
        actor_type="user",
        actor_id=user.id,
        subject_type="correlation_rule_version",
        subject_id=version.id,
        occurred_at=now,
        payload={
            "rule_key": rule_key,
            "version": version.version,
            "content_hash": version.content_hash,
        },
    )
    return version
