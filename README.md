# `arp-policy`

A minimal policy evaluator for the ARP Tool Registry.

## Policy format

Top-level keys:
- `Version`: optional version string.
- `Statement`: list of statements.

Statement keys:
- `Sid`: optional statement id for audit/debug.
- `Effect`: `Allow` or `Deny`.
- `Action`: string or list of strings.
- `Resource`: string or list of strings.
- `Condition`: optional map of operator to key/value map.

Supported condition operators:
- `StringEquals`
- `StringLike` (wildcards with `*`)

## Usage

```python
from arp_policy import Enforcer, Policy, emit_decision

policy = Policy.load("./config/policy/policy.dev.json")
enforcer = Enforcer(policy)

context = {
    "principal": "user:alice",
    "tenant": "acme",
    "environment": "dev",
    "request_id": "req-123",
}

decision = enforcer.authorize("tool:Invoke", "tool:finance/pay", context)
if not decision.allowed:
    raise Exception("policy denied")

# Audit event
record = emit_decision(
    decision,
    context,
    action="tool:Invoke",
    resource="tool:finance/pay",
    policy_hash=policy.policy_hash,
)
```

## Auth and identity

`arp-policy` is auth-agnostic. It does not validate credentials or issue identities.

The host service (Tool Registry, Runtime, Daemon) must:
- authenticate the caller using your chosen scheme (JWT, mTLS, API key, etc.)
- map verified identity attributes into the `context` dict (e.g., `principal`, `tenant`)
- avoid passing raw credentials into policy context

### Tool discovery filtering

```python
tools = [{"tool_id": "finance.pay", "metadata": {"labels": {"tier": "gold"}}}]
allowed = enforcer.filter_tools(tools, context)
```

## Context keys

Typical keys used in policy conditions:
- `principal`
- `tenant`
- `environment`
- `request_id`
- `tool.id`
- `tool.tags` (tool labels/annotations)
