"""Authentication: forged, altered, expired, and revoked credentials for users and agents."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.config import Settings
from aegis.provisioning import create_user
from aegis.security.agent_keys import format_key, parse_key
from aegis.security.tokens import TokenService
from support import PASSWORD, bearer


def _user_routes():
    return [
        ("GET", "/api/v1/auth/me"),
        ("GET", "/api/v1/assets"),
        ("POST", "/api/v1/assets"),
        ("GET", "/api/v1/agents"),
        ("POST", "/api/v1/agents"),
        ("GET", "/api/v1/resources"),
        ("POST", "/api/v1/resources"),
        ("GET", "/api/v1/policies"),
        ("POST", "/api/v1/policies"),
        ("GET", "/api/v1/approvals"),
        ("GET", "/api/v1/decisions"),
        ("GET", "/api/v1/audit/events"),
        ("GET", "/api/v1/audit/head"),
        ("POST", "/api/v1/audit/verify"),
        ("GET", "/api/v1/overview"),
        ("GET", "/api/v1/events"),
        ("GET", "/api/v1/incidents"),
        ("GET", "/api/v1/correlation-rules"),
    ]


@pytest.mark.parametrize("method, path", _user_routes())
def test_unauthenticated_requests_are_rejected(world, method, path):
    response = world.client.request(method, path)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"


def test_every_api_route_is_covered_by_an_auth_test(world):
    """A new route must either be listed above or be deliberately public."""
    public = {("POST", "/api/v1/auth/login"), ("GET", "/healthz")}
    for path, operations in world.app.openapi()["paths"].items():
        for method in operations:
            if (method.upper(), path) in public:
                continue
            url = path
            for parameter in ("id", "cid", "tool", "resource_id", "request_id", "approval_id",
                              "agent_id", "policy_id", "decision_id", "asset_id", "event_id",
                              "incident_id", "rule_key", "evidence_type", "evidence_id"):
                url = url.replace("{" + parameter + "}", str(uuid4()))
            assert "{" not in url, url
            response = world.client.request(method.upper(), url)
            assert response.status_code == 401, f"{method} {path}"


def test_gateway_rejects_missing_credentials(world):
    response = world.client.post(
        "/api/v1/gateway/actions",
        json={"idempotency_key": "k", "tool": "calculate", "resource_id": None, "params": {}},
    )
    assert response.status_code == 401
    assert world.spy.calls == []


@pytest.mark.parametrize(
    "key",
    [
        "not-a-key",
        "aegis_agent",
        "aegis_agent.not-a-uuid.not-a-uuid.secret",
        f"aegis_agent.{uuid4()}.{uuid4()}.",
        f"aegis_agent.{uuid4()}.{uuid4()}.guess",
        f"other.{uuid4()}.{uuid4()}.secret",
    ],
)
def test_forged_agent_keys_are_rejected(world, key):
    response = world.client.post(
        "/api/v1/gateway/actions",
        headers=bearer(key),
        json={"idempotency_key": "k", "tool": "calculate", "resource_id": None, "params": {}},
    )
    assert response.status_code == 401
    assert world.spy.calls == []


def test_wrong_secret_is_rejected_and_audited(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    parsed = parse_key(agent.key)
    forged = format_key(parsed.tenant_id, parsed.credential_id, "wrong-secret")

    response = world.client.post(
        "/api/v1/gateway/actions",
        headers=bearer(forged),
        json={"idempotency_key": "k", "tool": "calculate", "resource_id": None,
              "params": {"operator": "add", "a": 1, "b": 2}},
    )

    assert response.status_code == 401
    assert world.spy.calls == []
    events = tenant.audit_events("auth.agent_failed")
    assert len(events) == 1
    assert "wrong-secret" not in str(events[0])


def test_altering_the_tenant_segment_finds_no_credential(world, tenant):
    victim = world.tenant()
    victim.allow_everything()
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    parsed = parse_key(agent.key)
    forged = format_key(victim.id, parsed.credential_id, parsed.secret)

    response = world.client.post(
        "/api/v1/gateway/actions",
        headers=bearer(forged),
        json={"idempotency_key": "k", "tool": "calculate", "resource_id": None,
              "params": {"operator": "add", "a": 1, "b": 2}},
    )

    assert response.status_code == 401
    assert world.spy.calls == []


def test_revoked_credential_stops_working_immediately(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    params = {"operator": "add", "a": 1, "b": 2}
    assert agent.act("calculate", params=params).status_code == 200

    revoked = tenant.post(f"/agents/{agent.id}/credentials/{agent.credential_id}/revoke")
    assert revoked.status_code == 200

    assert agent.act("calculate", params=params).status_code == 401


def test_credentials_can_be_rotated(world, tenant):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    params = {"operator": "add", "a": 1, "b": 2}
    new_key = tenant.created(f"/agents/{agent.id}/credentials", {})["key"]
    tenant.post(f"/agents/{agent.id}/credentials/{agent.credential_id}/revoke")

    assert agent.act("calculate", params=params).status_code == 401
    assert (
        tenant.client.post(
            "/api/v1/gateway/actions",
            headers=bearer(new_key),
            json={"idempotency_key": "k", "tool": "calculate", "resource_id": None,
                  "params": params},
        ).status_code
        == 200
    )


def test_expired_credential_is_rejected(world, tenant, attacker_sql):
    tenant.allow_everything()
    agent = tenant.agent(tools=["calculate"])
    attacker_sql.execute(
        "UPDATE agent_credentials SET expires_at = now() - interval '1 second' WHERE id = %s",
        (agent.credential_id,),
    )
    assert agent.act("calculate", params={"operator": "add", "a": 1, "b": 2}).status_code == 401


def test_credential_of_another_agent_cannot_be_revoked_via_this_agent(tenant):
    first, second = tenant.agent(), tenant.agent()
    response = tenant.post(f"/agents/{first.id}/credentials/{second.credential_id}/revoke")
    assert response.status_code == 404


def test_secret_not_stored_or_returned_again(tenant, attacker_sql):
    agent = tenant.agent()
    secret = parse_key(agent.key).secret

    row = attacker_sql.execute(
        "SELECT secret_hash FROM agent_credentials WHERE id = %s", (agent.credential_id,)
    ).fetchone()
    assert secret.encode() not in bytes(row[0])

    detail = tenant.get(f"/agents/{agent.id}").text
    assert secret not in detail
    assert "secret_hash" not in detail
    for event in tenant.audit_events():
        assert secret not in str(event)


def test_password_is_hashed_with_argon2(tenant, attacker_sql):
    _ = tenant.admin
    row = attacker_sql.execute(
        "SELECT password_hash FROM users WHERE tenant_id = %s", (tenant.id,)
    ).fetchone()
    assert row[0].startswith("$argon2id$")
    assert PASSWORD not in row[0]


def test_login_failures_are_indistinguishable(world, tenant):
    _ = tenant.admin
    email = f"admin@{tenant.slug}.example.test"
    attempts = [
        {"tenant_slug": tenant.slug, "email": email, "password": "wrong"},
        {"tenant_slug": tenant.slug, "email": "nobody@example.test", "password": PASSWORD},
        {"tenant_slug": "no-such-tenant", "email": email, "password": PASSWORD},
    ]
    responses = [world.client.post("/api/v1/auth/login", json=body) for body in attempts]
    assert {response.status_code for response in responses} == {401}
    messages = {
        (response.json()["error"]["code"], response.json()["error"]["message"])
        for response in responses
    }
    assert len(messages) == 1


def test_failed_login_is_audited_without_the_password(world, tenant):
    _ = tenant.admin
    world.client.post(
        "/api/v1/auth/login",
        json={
            "tenant_slug": tenant.slug,
            "email": f"admin@{tenant.slug}.example.test",
            "password": "attempted-password",
        },
    )
    events = tenant.audit_events("auth.login_failed")
    assert len(events) == 1
    assert "attempted-password" not in str(events[0])


def test_inactive_user_cannot_log_in_or_use_an_existing_token(world, tenant, attacker_sql):
    headers = tenant.admin
    assert tenant.get("/auth/me", headers=headers).status_code == 200
    attacker_sql.execute("UPDATE users SET is_active = false WHERE tenant_id = %s", (tenant.id,))

    assert tenant.get("/auth/me", headers=headers).status_code == 401
    response = world.client.post(
        "/api/v1/auth/login",
        json={
            "tenant_slug": tenant.slug,
            "email": f"admin@{tenant.slug}.example.test",
            "password": PASSWORD,
        },
    )
    assert response.status_code == 401


def test_role_is_read_from_the_database_not_the_token(tenant, attacker_sql):
    headers = tenant.admin
    assert tenant.post("/policies", {"name": "first"}, headers=headers).status_code == 201
    attacker_sql.execute("UPDATE users SET role = 'viewer' WHERE tenant_id = %s", (tenant.id,))
    assert tenant.post("/policies", {"name": "second"}, headers=headers).status_code == 403


def _claims(tenant, user_id, **overrides):
    now = datetime.now(UTC)
    claims = {
        "iss": "aegis",
        "aud": "aegis-api",
        "sub": str(user_id),
        "tid": str(tenant.id),
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "jti": str(uuid4()),
    }
    claims.update(overrides)
    return {key: value for key, value in claims.items() if value is not None}


def test_alg_none_token_is_rejected(world, tenant):
    user_id = tenant.get("/auth/me").json()["id"]
    token = jwt.encode(_claims(tenant, user_id), key="", algorithm="none")
    assert tenant.get("/auth/me", headers=bearer(token)).status_code == 401


def test_token_signed_by_another_key_is_rejected(world, tenant):
    user_id = tenant.get("/auth/me").json()["id"]
    token = jwt.encode(_claims(tenant, user_id), Ed25519PrivateKey.generate(), algorithm="EdDSA")
    assert tenant.get("/auth/me", headers=bearer(token)).status_code == 401


def test_hmac_token_using_the_public_key_is_rejected(world, tenant, jwt_key_path):
    user_id = tenant.get("/auth/me").json()["id"]
    token = jwt.encode(
        _claims(tenant, user_id),
        "a-shared-secret-of-sufficient-length-for-hs256-signing",
        algorithm="HS256",
    )
    assert tenant.get("/auth/me", headers=bearer(token)).status_code == 401


def _signer(jwt_key_path, urls):
    return TokenService(
        Settings(
            _env_file=None,
            environment="test",
            database_url=urls.app,
            jwt_private_key_path=jwt_key_path,
        )
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "someone-else"},
        {"aud": "another-service"},
        {"exp": datetime(2020, 1, 1, tzinfo=UTC)},
        {"exp": None},
        {"jti": None},
        {"tid": None},
        {"tid": "not-a-uuid"},
    ],
)
def test_tokens_with_bad_claims_are_rejected(tenant, jwt_key_path, urls, overrides):
    user_id = tenant.get("/auth/me").json()["id"]
    signer = _signer(jwt_key_path, urls)
    token = jwt.encode(
        _claims(tenant, user_id, **overrides), signer._private_key, algorithm="EdDSA"
    )
    assert tenant.get("/auth/me", headers=bearer(token)).status_code == 401


def test_valid_token_for_a_user_outside_the_claimed_tenant_is_rejected(
    world, tenant, jwt_key_path, urls
):
    other = world.tenant()
    other_user = other.get("/auth/me").json()["id"]
    signer = _signer(jwt_key_path, urls)
    token = signer.issue(user_id=other_user, tenant_id=tenant.id)
    assert tenant.get("/auth/me", headers=bearer(token)).status_code == 401


def test_user_created_in_one_tenant_cannot_log_in_to_another(world, tenant, urls):
    other = world.tenant()
    create_user(urls.owner, other.id, email="person@example.test", password=PASSWORD, role="admin")
    response = world.client.post(
        "/api/v1/auth/login",
        json={"tenant_slug": tenant.slug, "email": "person@example.test", "password": PASSWORD},
    )
    assert response.status_code == 401
