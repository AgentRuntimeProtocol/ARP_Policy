from __future__ import annotations

from typing import Any, Mapping

from .enforcer import Decision


def emit_decision(
    decision: Decision,
    context: Mapping[str, Any],
    *,
    action: str,
    tool_id: str | None = None,
    resource: str | None = None,
    policy_hash: str | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "decision": "allow" if decision.allowed else "deny",
        "statement_id": decision.matched_statement_id,
        "action": action,
        "resource": resource,
        "tool_id": tool_id,
        "request_id": decision.request_id,
    }
    for key in ("principal", "tenant", "environment"):
        if key in context and context[key] is not None:
            event[key] = context[key]
    if policy_hash:
        event["policy_hash"] = policy_hash
    return event
