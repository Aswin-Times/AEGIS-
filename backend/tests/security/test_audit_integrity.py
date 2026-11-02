"""Audit integrity: attempted modification, and detection of tampering that succeeds."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC
from uuid import uuid4

import psycopg
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from aegis.audit.chain import GENESIS_HASH, append_event, verify_chain
from aegis.canonical import canonical_hash


def _chain(db, tenant, count=3):
    with db.tenant_transaction(tenant) as session:
        for number in range(count):
            append_event(
                session,
                tenant,
                event_type="test.event",
                actor_type="system",
                payload={"number": number},
            )


def _verify(db, tenant):
    with db.tenant_transaction(tenant) as session:
        return verify_chain(session, tenant)


def _as_attacker(attacker_sql, statements):
    """Disable the protective triggers and tamper, as a superuser could."""
    attacker_sql.execute("ALTER TABLE audit_events DISABLE TRIGGER USER")
    try:
        for statement, params in statements:
            attacker_sql.execute(statement, params)
    finally:
        attacker_sql.execute("ALTER TABLE audit_events ENABLE TRIGGER USER")


def test_untampered_chain_verifies(db, new_tenant):
    tenant = new_tenant()
    _chain(db, tenant)
    result = _verify(db, tenant)
    assert result.valid
    assert result.events_checked == 4  # tenant.provisioned + 3
    assert result.head_seq == 4


def test_first_event_links_to_genesis(db, new_tenant, attacker_sql):
    tenant = new_tenant()
    row = attacker_sql.execute(
        "SELECT prev_hash FROM audit_events WHERE tenant_id = %s AND seq = 1", (tenant,)
    ).fetchone()
    assert row[0] == GENESIS_HASH


@pytest.mark.parametrize("statement", ["UPDATE audit_events SET event_type = 'x'",
                                       "DELETE FROM audit_events",
                                       "TRUNCATE audit_events"])
def test_runtime_role_cannot_mutate_audit_events(db, new_tenant, statement):
    tenant = new_tenant()
    with pytest.raises(ProgrammingError), db.tenant_transaction(tenant) as session:
        session.execute(text(statement))
    assert _verify(db, tenant).valid


@pytest.mark.parametrize("statement", ["UPDATE audit_events SET event_type = 'x'",
                                       "DELETE FROM audit_events",
                                       "TRUNCATE audit_events"])
def test_owner_role_is_blocked_by_triggers(urls, new_tenant, statement):
    tenant = new_tenant()
    engine = create_engine(urls.owner)
    try:
        # TRUNCATE now hits the security_events foreign key first. Either refusal protects the log.
        refused = "append-only|referenced in a foreign key"
        with pytest.raises(DBAPIError, match=refused), engine.begin() as connection:
            connection.execute(
                text("SELECT set_config('app.tenant_id', :tenant, true)"),
                {"tenant": str(tenant)},
            )
            connection.execute(text(statement))
    finally:
        engine.dispose()


def test_modified_content_fails_verification(db, new_tenant, attacker_sql):
    tenant = new_tenant()
    _chain(db, tenant)
    _as_attacker(
        attacker_sql,
        [("UPDATE audit_events SET payload = '{\"number\": 99}' "
          "WHERE tenant_id = %s AND seq = 3", (tenant,))],
    )
    result = _verify(db, tenant)
    assert not result.valid
    assert result.failure_seq == 3
    assert result.failure_reason == "CONTENT_MODIFIED"


def test_modified_actor_fails_verification(db, new_tenant, attacker_sql):
    tenant = new_tenant()
    _chain(db, tenant)
    _as_attacker(
        attacker_sql,
        [("UPDATE audit_events SET actor_id = %s WHERE tenant_id = %s AND seq = 2",
          (uuid4(), tenant))],
    )
    assert _verify(db, tenant).failure_reason == "CONTENT_MODIFIED"


def test_removed_middle_event_fails_verification(db, new_tenant, attacker_sql):
    tenant = new_tenant()
    _chain(db, tenant)
    _as_attacker(
        attacker_sql,
        [("DELETE FROM audit_events WHERE tenant_id = %s AND seq = 2", (tenant,))],
    )
    result = _verify(db, tenant)
    assert not result.valid
    assert result.failure_seq == 2
    assert result.failure_reason == "MISSING_EVENT"


def test_removed_tail_fails_verification(db, new_tenant, attacker_sql):
    tenant = new_tenant()
    _chain(db, tenant)
    _as_attacker(
        attacker_sql,
        [("DELETE FROM audit_events WHERE tenant_id = %s AND seq = 4", (tenant,))],
    )
    result = _verify(db, tenant)
    assert not result.valid
    assert result.failure_reason == "MISSING_TAIL"


def test_reordered_events_fail_verification(db, new_tenant, attacker_sql):
    tenant = new_tenant()
    _chain(db, tenant)
    _as_attacker(
        attacker_sql,
        [
            ("UPDATE audit_events SET seq = 1000 WHERE tenant_id = %s AND seq = 2", (tenant,)),
            ("UPDATE audit_events SET seq = 2 WHERE tenant_id = %s AND seq = 3", (tenant,)),
            ("UPDATE audit_events SET seq = 3 WHERE tenant_id = %s AND seq = 1000", (tenant,)),
        ],
    )
    result = _verify(db, tenant)
    assert not result.valid
    assert result.failure_seq == 2


def test_recomputing_one_events_hash_breaks_the_link_to_the_next(db, new_tenant, attacker_sql):
    """An attacker who fixes the edited event's own hash is caught by the next event's link."""
    tenant = new_tenant()
    _chain(db, tenant)
    row = attacker_sql.execute(
        """
        SELECT id, seq, prev_hash, event_type, actor_type, subject_type, subject_id, occurred_at
        FROM audit_events WHERE tenant_id = %s AND seq = 2
        """,
        (tenant,),
    ).fetchone()
    forged_payload = {"number": 99}
    forged_hash = canonical_hash(
        {
            "id": str(row[0]),
            "tenant_id": str(tenant),
            "seq": row[1],
            "prev_hash": row[2],
            "event_type": row[3],
            "actor_type": row[4],
            "actor_id": None,
            "correlation_id": None,
            "subject_type": row[5],
            "subject_id": None if row[6] is None else str(row[6]),
            "policy_version_id": None,
            "occurred_at": row[7].astimezone(UTC).isoformat(),
            "payload": forged_payload,
        }
    )
    _as_attacker(
        attacker_sql,
        [("UPDATE audit_events SET payload = %s, event_hash = %s WHERE id = %s",
          (json.dumps(forged_payload), forged_hash, row[0]))],
    )

    result = _verify(db, tenant)

    assert not result.valid
    assert result.failure_seq == 3
    assert result.failure_reason == "BROKEN_LINK"


def test_tampered_head_fails_verification(db, new_tenant, attacker_sql):
    tenant = new_tenant()
    _chain(db, tenant)
    attacker_sql.execute(
        "UPDATE audit_chain_heads SET head_hash = %s WHERE tenant_id = %s", ("f" * 64, tenant)
    )
    assert _verify(db, tenant).failure_reason == "HEAD_MISMATCH"


def test_documented_limitation_full_chain_rewrite_is_not_detected(db, new_tenant, attacker_sql):
    """Records threat T11: a superuser who recomputes every hash and the head goes unseen.

    If this ever fails, the guarantee got stronger, and the docs should be updated.
    """
    tenant = new_tenant()
    _chain(db, tenant, count=1)
    rows = attacker_sql.execute(
        """
        SELECT id, seq, prev_hash, event_type, actor_type, actor_id, correlation_id,
               subject_type, subject_id, policy_version_id, occurred_at, payload
        FROM audit_events WHERE tenant_id = %s ORDER BY seq
        """,
        (tenant,),
    ).fetchall()

    previous = GENESIS_HASH
    statements = []
    for row in rows:
        payload = {"rewritten": True}
        new_hash = canonical_hash(
            {
                "id": str(row[0]),
                "tenant_id": str(tenant),
                "seq": row[1],
                "prev_hash": previous,
                "event_type": row[3],
                "actor_type": row[4],
                "actor_id": None,
                "correlation_id": None,
                "subject_type": row[7],
                "subject_id": None if row[8] is None else str(row[8]),
                "policy_version_id": None,
                "occurred_at": row[10].astimezone(UTC).isoformat(),
                "payload": payload,
            }
        )
        statements.append(
            (
                "UPDATE audit_events SET payload = %s, prev_hash = %s, event_hash = %s "
                "WHERE id = %s",
                (json.dumps(payload), previous, new_hash, row[0]),
            )
        )
        previous = new_hash
    _as_attacker(attacker_sql, statements)
    attacker_sql.execute(
        "UPDATE audit_chain_heads SET head_hash = %s WHERE tenant_id = %s", (previous, tenant)
    )

    assert _verify(db, tenant).valid is True


def test_float_in_payload_is_refused(db, new_tenant):
    tenant = new_tenant()
    with pytest.raises(TypeError), db.tenant_transaction(tenant) as session:
        append_event(
            session, tenant, event_type="x", actor_type="system", payload={"value": [1.5]}
        )


def test_concurrent_appends_produce_a_linear_chain(db, new_tenant):
    tenant = new_tenant()

    def append(number: int) -> None:
        with db.tenant_transaction(tenant) as session:
            append_event(
                session,
                tenant,
                event_type="test.concurrent",
                actor_type="system",
                payload={"number": number},
            )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(40)))

    result = _verify(db, tenant)
    assert result.valid
    assert result.events_checked == 41


def test_chains_are_per_tenant(db, new_tenant, attacker_sql):
    tenant_a, tenant_b = new_tenant(), new_tenant()
    _chain(db, tenant_a)
    _as_attacker(
        attacker_sql,
        [("UPDATE audit_events SET event_type = 'forged' WHERE tenant_id = %s AND seq = 2",
          (tenant_a,))],
    )
    assert not _verify(db, tenant_a).valid
    assert _verify(db, tenant_b).valid


def test_superuser_connection_string_is_not_the_runtime_url(urls):
    with psycopg.connect(urls.superuser) as connection:
        assert connection.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
                                  ).fetchone()[0] is True
    assert "aegis_app" in urls.app
