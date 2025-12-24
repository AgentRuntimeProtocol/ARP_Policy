from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, MutableMapping, TypeVar

from .errors import PolicyEvaluationError
from .policy import Policy, Statement
from .utils import match_pattern, resolve_context_value


T = TypeVar("T")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    matched_statement_id: str | None
    reason: str
    request_id: str | None = None


class Enforcer:
    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    @property
    def policy(self) -> Policy:
        return self._policy

    def authorize(self, action: str, resource: str, context: Mapping[str, Any] | None = None) -> Decision:
        if not isinstance(action, str) or not action:
            raise PolicyEvaluationError("action must be a non-empty string")
        if not isinstance(resource, str) or not resource:
            raise PolicyEvaluationError("resource must be a non-empty string")
        ctx = context or {}

        matched_allow: Statement | None = None
        for statement in self._policy.statements:
            if not _statement_matches(statement, action, resource, ctx):
                continue
            if statement.effect == "Deny":
                return Decision(
                    allowed=False,
                    matched_statement_id=statement.sid,
                    reason="explicit_deny",
                    request_id=_request_id(ctx),
                )
            if matched_allow is None:
                matched_allow = statement

        if matched_allow is not None:
            return Decision(
                allowed=True,
                matched_statement_id=matched_allow.sid,
                reason="explicit_allow",
                request_id=_request_id(ctx),
            )

        return Decision(
            allowed=False,
            matched_statement_id=None,
            reason="default_deny",
            request_id=_request_id(ctx),
        )

    def filter_tools(self, tools: Iterable[T], context: Mapping[str, Any] | None = None) -> list[T]:
        ctx = context or {}
        allowed: list[T] = []
        for tool in tools:
            tool_id = _tool_id(tool)
            if tool_id is None:
                raise PolicyEvaluationError("tool is missing tool_id")
            tool_context = _with_tool_context(ctx, tool)
            decision = self.authorize("tool:Discover", f"tool:{tool_id}", tool_context)
            if decision.allowed:
                allowed.append(tool)
        return allowed


def _statement_matches(
    statement: Statement, action: str, resource: str, context: Mapping[str, Any]
) -> bool:
    if not _matches_any(action, statement.actions):
        return False
    if not _matches_any(resource, statement.resources):
        return False
    return _conditions_match(statement.condition, context)


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    return any(match_pattern(value, pattern) for pattern in patterns)


def _conditions_match(condition: dict[str, dict[str, Any]] | None, context: Mapping[str, Any]) -> bool:
    if condition is None:
        return True
    for operator, key_map in condition.items():
        if operator == "StringEquals":
            if not _eval_string_equals(key_map, context):
                return False
        elif operator == "StringLike":
            if not _eval_string_like(key_map, context):
                return False
        else:
            raise PolicyEvaluationError(f"Unsupported condition operator: {operator}")
    return True


def _eval_string_equals(key_map: Any, context: Mapping[str, Any]) -> bool:
    if not isinstance(key_map, Mapping):
        raise PolicyEvaluationError("StringEquals must be an object")
    for key, expected in key_map.items():
        actual = resolve_context_value(context, key)
        if actual is None:
            return False
        if not _match_values(actual, expected, lambda a, b: a == b):
            return False
    return True


def _eval_string_like(key_map: Any, context: Mapping[str, Any]) -> bool:
    if not isinstance(key_map, Mapping):
        raise PolicyEvaluationError("StringLike must be an object")
    for key, expected in key_map.items():
        actual = resolve_context_value(context, key)
        if actual is None:
            return False
        if not _match_values(actual, expected, lambda a, b: match_pattern(a, b)):
            return False
    return True


def _match_values(actual: Any, expected: Any, matcher) -> bool:
    actual_values = _coerce_values(actual)
    expected_values = _coerce_values(expected)
    if not actual_values or not expected_values:
        return False
    for actual_value in actual_values:
        for expected_value in expected_values:
            if matcher(actual_value, expected_value):
                return True
    return False


def _coerce_values(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        values = list(value)
    else:
        values = [value]

    result: list[str] = []
    for item in values:
        if isinstance(item, dict):
            raise PolicyEvaluationError("Condition values cannot be objects")
        if item is None:
            continue
        if isinstance(item, bool):
            result.append("true" if item else "false")
        else:
            result.append(str(item))
    return result


def _with_tool_context(context: Mapping[str, Any], tool: Any) -> dict[str, Any]:
    merged: dict[str, Any] = dict(context)
    tool_id = _tool_id(tool)
    if tool_id is not None:
        merged["tool.id"] = tool_id
    tags = _tool_tags(tool)
    if tags:
        merged["tool.tags"] = tags
    return merged


def _tool_id(tool: Any) -> str | None:
    if hasattr(tool, "tool_id"):
        return getattr(tool, "tool_id")
    if isinstance(tool, Mapping) and "tool_id" in tool:
        return tool["tool_id"]
    return None


def _tool_tags(tool: Any) -> MutableMapping[str, Any]:
    tags: dict[str, Any] = {}
    metadata = None
    if hasattr(tool, "metadata"):
        metadata = getattr(tool, "metadata")
    elif isinstance(tool, Mapping):
        metadata = tool.get("metadata")

    if metadata is not None:
        labels = getattr(metadata, "labels", None) if not isinstance(metadata, Mapping) else metadata.get("labels")
        annotations = (
            getattr(metadata, "annotations", None)
            if not isinstance(metadata, Mapping)
            else metadata.get("annotations")
        )
        if isinstance(labels, Mapping):
            tags.update(labels)
        if isinstance(annotations, Mapping):
            tags.update(annotations)

    if isinstance(tool, Mapping) and "tags" in tool and isinstance(tool["tags"], Mapping):
        tags.update(tool["tags"])
    return tags


def _request_id(context: Mapping[str, Any]) -> str | None:
    value = resolve_context_value(context, "request_id")
    if value is None:
        return None
    return str(value)
