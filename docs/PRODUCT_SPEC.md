# AEGIS Product Specification

**AEGIS: AI Security, Governance & Control Platform.**
*Trust your AI. Verify its actions. Govern its behavior.*

## Problem

Organizations run AI applications and autonomous agents that hold real credentials.
Possessing technical access to a resource does not authorize every use of it, yet
most deployments have no enforcement point between "the agent decided to" and "it
happened". AEGIS is that enforcement point, plus the records needed to prove what
occurred.

## Questions the platform must answer

| # | Question | Answered by |
|---|----------|-------------|
| 1 | What AI applications and agents exist? | Asset and agent registry |
| 2 | What can each agent access? | Tool and resource grants |
| 3 | What actions are agents attempting? | Action requests and decisions |
| 4 | Are those actions authorized? | Deterministic policy engine |
| 5 | Can unsafe actions be stopped before execution? | Security gateway |
| 6 | Can activity be investigated with verifiable evidence? | Audit chain, incidents |
| 7 | Can governance be demonstrated? | Policy versions, approvals, assessments |

## Scope boundary

AEGIS protects **only operations routed through the gateway's controlled execution
interface**. An agent holding its own database password or API key can bypass AEGIS,
and AEGIS cannot detect that. Deployments must hold the real credentials behind the
gateway rather than give them to agents. The product must never claim otherwise.

## Users

| Role | Can do |
|------|--------|
| `admin` | Manage assets, agents, grants, policies; everything a reviewer and viewer can do |
| `reviewer` | Approve or reject held actions; read everything |
| `viewer` | Read-only access to registry, decisions, audit |
| Agent (non-human) | Submit action requests and read its own requests. Nothing else |

## MVP features, in build order

1. **AI asset registry**: register applications and agents, owner, risk class, grants, activate or deactivate.
2. **Deterministic policy engine**: allow, deny, approval required.
3. **Controlled gateway**: synthetic tools only. No shell and no general network access.
4. **Human approval workflow**: bound to one exact action, single use.
5. **Security events and incidents**: deterministic correlation.
6. **Audit integrity**: append-only store, per-tenant hash chain, verification.
7. **Governance dashboard**: real backend data only.

## Required policies

1. An agent may read an explicitly authorized document.
2. An agent may not invoke an unapproved tool.
3. An agent may not transmit sensitive data to an unapproved destination.
4. An action requiring approval remains unexecuted until approved.
5. A disabled agent cannot execute protected actions.
6. An agent cannot access another tenant's resources.
7. Malformed or incomplete action requests are rejected.

## Non-goals for the MVP

- Certifying compliance. Mappings describe implemented controls only.
- Claiming advanced threat detection. Only simple, deterministic patterns ship.
- Inspecting free-text content for secrets as a security boundary (see `THREAT_MODEL.md` T3).
- Running as a network proxy that intercepts traffic agents did not send to it.
- Microservices, Kafka, graph databases, or Kubernetes.

## Honesty rules for the product

- No fabricated incidents, metrics, or enforcement results.
- All demonstration data is labeled synthetic in storage (`is_synthetic`) and in the UI.
- AI output is labeled as a hypothesis and can never authorize execution.
- Every count on the dashboard comes from a stored record.
