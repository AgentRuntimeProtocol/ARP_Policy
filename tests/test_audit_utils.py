from arp_policy import Decision
from arp_policy.audit import emit_decision
from arp_policy.utils import resolve_context_value


def test_emit_decision_includes_context_and_policy_hash():
    decision = Decision(
        allowed=True,
        matched_statement_id="AllowAll",
        reason="explicit_allow",
        request_id="req-1",
    )
    context = {"principal": "alice", "tenant": "acme", "environment": None}

    event = emit_decision(
        decision,
        context,
        action="tool:Invoke",
        tool_id="tool:finance/pay",
        resource="tool:finance/pay",
        policy_hash="hash-123",
    )

    assert event["decision"] == "allow"
    assert event["statement_id"] == "AllowAll"
    assert event["action"] == "tool:Invoke"
    assert event["resource"] == "tool:finance/pay"
    assert event["tool_id"] == "tool:finance/pay"
    assert event["request_id"] == "req-1"
    assert event["principal"] == "alice"
    assert event["tenant"] == "acme"
    assert "environment" not in event
    assert event["policy_hash"] == "hash-123"


def test_resolve_context_value_nested_and_fallback():
    context = {"principal": "alice"}
    assert resolve_context_value(context, "principal") == "alice"

    nested = {"tool": {"id": "tool:alpha"}}
    assert resolve_context_value(nested, "tool.id") == "tool:alpha"

    flat = {"tool.tags": {"tier": "gold"}}
    assert resolve_context_value(flat, "tool.tags.tier") == "gold"


def test_resolve_context_value_missing_returns_none():
    assert resolve_context_value({}, "missing") is None
    assert resolve_context_value({}, "tool.id") is None
    assert resolve_context_value({"tool": {}}, "tool.id") is None
    assert resolve_context_value({"tool.tags": {}}, "tool.tags.tier") is None
