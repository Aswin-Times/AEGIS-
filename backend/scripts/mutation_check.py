"""Prove the security tests can fail: remove each control and require a test to catch it.

Works on a temporary copy of the backend, so the source tree is never touched. A control
whose removal goes unnoticed is reported as SURVIVED, and the script exits non-zero.

    python scripts/mutation_check.py
"""

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
MIGRATION = "migrations/versions/0001_initial.py"
GATEWAY = "src/aegis/gateway/service.py"
SEC = "tests/security"


@dataclass(frozen=True)
class Mutation:
    name: str
    file: str
    old: str
    new: str
    tests: str


MUTATIONS = [
    Mutation("Deny path reaches the executor", GATEWAY,
             "elif evaluation.outcome is Outcome.ALLOW:", "else:", f"{SEC}/test_gateway.py"),
    Mutation("Engine failure yields allow", GATEWAY,
             'return Evaluation(Outcome.DENY, "POLICY_EVALUATION_ERROR")',
             'return Evaluation(Outcome.ALLOW, "POLICY_EVALUATION_ERROR")',
             f"{SEC}/test_policy_enforcement.py"),
    Mutation("Policy content hash not checked", GATEWAY,
             "if version is None or sha256_hex(version.document_canonical) "
             "!= version.content_hash:",
             "if version is None:", f"{SEC}/test_policy_enforcement.py"),
    Mutation("Pending approval can execute", GATEWAY,
             'if approval is None or approval.status != "APPROVED":',
             'if approval is None or approval.status not in ("APPROVED", "PENDING"):',
             f"{SEC}/test_approval_safety.py"),
    Mutation("Re-evaluation at execution ignored", GATEWAY,
             "if evaluation.outcome is Outcome.DENY:\n                refused",
             "if False:\n                refused", f"{SEC}/test_approval_safety.py"),
    Mutation("Action hash not rechecked", GATEWAY,
             "elif recomputed != approval.action_hash or recomputed != request.action_hash:",
             "elif False:", f"{SEC}/test_approval_safety.py"),
    Mutation("Approval expiry not checked at execution", GATEWAY,
             "if now >= approval.expires_at:\n            refused", "if False:\n            refused",
             f"{SEC}/test_approval_safety.py"),
    Mutation("Idempotency key content not compared", GATEWAY,
             "if existing is not None and existing.action_hash != action_hash:", "if False:",
             f"{SEC}/test_gateway.py"),
    Mutation("Agent can execute another agent's request", GATEWAY,
             "if request is None or request.agent_id != agent.id:\n            raise NotFound()\n"
             "        # The row lock",
             "if request is None:\n            raise NotFound()\n        # The row lock",
             f"{SEC}/test_approval_safety.py"),
    Mutation("Audit write failure not fatal", GATEWAY,
             "    except Exception as error:\n        logger.exception(\"protected action failed "
             "closed\")\n        raise ServiceUnavailable() from error",
             "    except Exception as error:\n        logger.exception(\"protected action failed "
             "closed\")\n        return None", f"{SEC}/test_gateway.py"),
    Mutation("Engine ignores tool grant", "src/aegis/policy/engine.py",
             'if not facts.tool_granted:\n        return "TOOL_NOT_GRANTED"', "",
             "tests/unit/test_policy_engine.py"),
    Mutation("Engine ignores destination clearance", "src/aegis/policy/engine.py",
             'return "DESTINATION_CLEARANCE_INSUFFICIENT"', "pass",
             "tests/unit/test_policy_engine.py"),
    Mutation("Engine default allows", "src/aegis/policy/engine.py",
             'return Evaluation(Outcome.DENY, "NO_MATCHING_RULE")',
             'return Evaluation(Outcome.ALLOW, "NO_MATCHING_RULE")',
             "tests/unit/test_policy_engine.py"),
    Mutation("Hash ignores payload", "src/aegis/audit/chain.py",
             '"payload": event.payload,', "", f"{SEC}/test_audit_integrity.py"),
    Mutation("Hash ignores previous hash", "src/aegis/audit/chain.py",
             'if event.prev_hash != previous_hash:', 'if False:',
             f"{SEC}/test_audit_integrity.py"),
    Mutation("Verification ignores head", "src/aegis/audit/chain.py",
             "if previous_hash != head.head_hash:", "if False:",
             f"{SEC}/test_audit_integrity.py"),
    Mutation("Verification ignores tail", "src/aegis/audit/chain.py",
             "if checked != head.seq:", "if False:", f"{SEC}/test_audit_integrity.py"),
    Mutation("Audit head not locked", "src/aegis/audit/chain.py",
             "select(AuditChainHead).where(AuditChainHead.tenant_id == tenant_id)"
             ".with_for_update()\n",
             "select(AuditChainHead).where(AuditChainHead.tenant_id == tenant_id)\n",
             f"{SEC}/test_audit_integrity.py"),
    Mutation("Tenant context not transaction-local", "src/aegis/db/session.py",
             "set_config('app.tenant_id', :tenant, true)",
             "set_config('app.tenant_id', :tenant, false)",
             f"{SEC}/test_tenant_isolation_db.py"),
    Mutation("Revoked credential accepted", "src/aegis/security/authentication.py",
             "and credential.revoked_at is None", "", f"{SEC}/test_authn.py"),
    Mutation("Expired credential accepted", "src/aegis/security/authentication.py",
             "and (credential.expires_at is None or credential.expires_at > now)", "",
             f"{SEC}/test_authn.py"),
    Mutation("Wrong agent secret accepted", "src/aegis/security/authentication.py",
             "            and matched\n", "", f"{SEC}/test_authn.py"),
    Mutation("Inactive user accepted", "src/aegis/security/authentication.py",
             "if user is None or not user.is_active:", "if user is None:",
             f"{SEC}/test_authn.py"),
    Mutation("JWT audience not required", "src/aegis/security/tokens.py",
             "audience=self._audience,", 'options_placeholder=None,'.replace(
                 "options_placeholder=None,", 'audience=[self._audience, "another-service"],'),
             f"{SEC}/test_authn.py"),
    Mutation("Role checks removed", "src/aegis/api/dependencies.py",
             "if user.role not in roles:", "if False:", f"{SEC}/test_authz.py"),
    Mutation("Reviewer identity not recorded", "src/aegis/approvals/service.py",
             "approval.decided_by = user.id", "pass", f"{SEC}/test_approval_safety.py"),
    Mutation("Approval state machine not checked", "src/aegis/approvals/service.py",
             "if not can_transition(approval.status, target):", "if False:",
             f"{SEC}/test_approval_safety.py"),
    Mutation("RLS not forced", MIGRATION,
             'f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",', "",
             f"{SEC}/test_tenant_isolation_db.py"),
    Mutation("RLS not enabled on tenant tables", MIGRATION,
             'f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",', "",
             f"{SEC}/test_tenant_isolation_db.py"),
    Mutation("Runtime role may update audit events", MIGRATION,
             '"GRANT SELECT, INSERT ON audit_events TO aegis_app",',
             '"GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON audit_events TO aegis_app",',
             f"{SEC}/test_audit_integrity.py"),
    Mutation("Append-only trigger absent", MIGRATION,
             'for table in ("audit_events", "policy_decisions", "policy_versions")',
             'for table in ("policy_decisions", "policy_versions")',
             f"{SEC}/test_audit_integrity.py"),
    Mutation("Approval transition trigger absent", MIGRATION,
             "CREATE TRIGGER approvals_transition BEFORE UPDATE OR DELETE ON approvals\n"
             "    FOR EACH ROW EXECUTE FUNCTION aegis_approval_transition()",
             "SELECT 1", f"{SEC}/test_approval_safety.py"),
    Mutation("Runtime role may edit policy versions", MIGRATION,
             '"GRANT SELECT, INSERT ON policy_versions TO aegis_app",',
             '"GRANT SELECT, INSERT, UPDATE, DELETE ON policy_versions TO aegis_app",',
             f"{SEC}/test_policy_versions.py"),
    Mutation("Composite tenant foreign key absent", MIGRATION,
             "FOREIGN KEY (tenant_id, asset_id) REFERENCES ai_assets (tenant_id, id)",
             "FOREIGN KEY (asset_id) REFERENCES ai_assets (id)",
             f"{SEC}/test_tenant_isolation_db.py"),
    Mutation("Execution uniqueness absent", MIGRATION,
             "UNIQUE (tenant_id, request_id),\n        FOREIGN KEY (tenant_id, request_id) "
             "REFERENCES action_requests (tenant_id, id)\n    )\n    \"\"\",\n    \"\"\"\n"
             "    CREATE TABLE simulated_outbox",
             "FOREIGN KEY (tenant_id, request_id) REFERENCES action_requests (tenant_id, id)\n"
             "    )\n    \"\"\",\n    \"\"\"\n    CREATE TABLE simulated_outbox",
             f"{SEC}/test_tenant_isolation_db.py"),
]


def run_tests(root: Path, tests: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(root / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(
        [sys.executable, "-m", "pytest", tests, "-x", "-q", "--tb=no", "--show-capture=no",
         "-p", "no:cacheprovider"],
        cwd=root, env=env, capture_output=True, text=True, timeout=600,
    )


def main() -> int:
    survivors = []
    with tempfile.TemporaryDirectory(prefix="aegis-mutation-") as temporary:
        root = Path(temporary) / "backend"
        root.mkdir()
        for item in ("src", "migrations", "tests", "alembic.ini", "pyproject.toml"):
            source = BACKEND / item
            if source.is_dir():
                shutil.copytree(source, root / item,
                                ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
            else:
                shutil.copy(source, root / item)

        for mutation in MUTATIONS:
            path = root / mutation.file
            original = path.read_text(encoding="utf-8")
            if mutation.old not in original:
                print(f"STALE     {mutation.name}: target text not found", flush=True)
                survivors.append(mutation.name)
                continue
            path.write_text(original.replace(mutation.old, mutation.new, 1), encoding="utf-8")
            try:
                result = run_tests(root, mutation.tests)
            finally:
                path.write_text(original, encoding="utf-8")
            lines = result.stdout.strip().splitlines()
            summary = lines[-1] if lines else ""
            failing = [line for line in lines if line.startswith(("FAILED", "ERROR"))]
            if result.returncode == 0:
                print(f"SURVIVED  {mutation.name} ({mutation.tests})", flush=True)
                survivors.append(mutation.name)
            else:
                caught_by = failing[0].split(" ")[1].split("::")[-1] if failing else summary
                print(f"caught    {mutation.name} <- {caught_by}", flush=True)

    print(f"\n{len(MUTATIONS) - len(survivors)} of {len(MUTATIONS)} removed controls were caught.")
    if survivors:
        print("Not caught:", *survivors, sep="\n  ")
    return 1 if survivors else 0


if __name__ == "__main__":
    raise SystemExit(main())
