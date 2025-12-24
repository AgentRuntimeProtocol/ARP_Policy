from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from .errors import PolicyParseError


@dataclass(frozen=True)
class Statement:
    effect: str
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    condition: dict[str, dict[str, Any]] | None
    sid: str | None


@dataclass(frozen=True)
class Policy:
    version: str | None
    statements: tuple[Statement, ...]
    raw: dict[str, Any]
    policy_hash: str

    @classmethod
    def load(cls, path_or_dict: str | Path | Mapping[str, Any]) -> "Policy":
        if isinstance(path_or_dict, (str, Path)):
            path = Path(path_or_dict)
            try:
                raw_text = path.read_text(encoding="utf-8")
            except OSError as exc:  # pragma: no cover - IO errors
                raise PolicyParseError(f"Failed to read policy file: {path}") from exc
            try:
                data = json.loads(raw_text)
            except json.JSONDecodeError as exc:
                raise PolicyParseError(f"Invalid JSON in policy file: {path}") from exc
        elif isinstance(path_or_dict, Mapping):
            data = dict(path_or_dict)
        else:
            raise PolicyParseError("Policy input must be a path or dict")
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> "Policy":
        if not isinstance(data, dict):
            raise PolicyParseError("Policy must be a JSON object")
        version = data.get("Version")
        statements_raw = data.get("Statement")
        if statements_raw is None:
            raise PolicyParseError("Policy must include Statement")
        if isinstance(statements_raw, dict):
            statements_list: Sequence[dict[str, Any]] = [statements_raw]
        elif isinstance(statements_raw, list):
            statements_list = statements_raw
        else:
            raise PolicyParseError("Statement must be an object or list")

        statements: list[Statement] = []
        for index, statement in enumerate(statements_list):
            if not isinstance(statement, dict):
                raise PolicyParseError(f"Statement[{index}] must be an object")
            statements.append(_parse_statement(statement, index))

        canonical = _canonical_json(data)
        policy_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return cls(
            version=version,
            statements=tuple(statements),
            raw=data,
            policy_hash=policy_hash,
        )


def _parse_statement(statement: dict[str, Any], index: int) -> Statement:
    sid = statement.get("Sid") or statement.get("statement_id")
    effect = statement.get("Effect")
    if not isinstance(effect, str):
        raise PolicyParseError(f"Statement[{index}].Effect must be a string")
    effect_normalized = effect.strip().title()
    if effect_normalized not in {"Allow", "Deny"}:
        raise PolicyParseError(f"Statement[{index}].Effect must be Allow or Deny")

    actions = _normalize_string_list(statement.get("Action"), f"Statement[{index}].Action")
    resources = _normalize_string_list(statement.get("Resource"), f"Statement[{index}].Resource")

    condition = statement.get("Condition")
    if condition is not None and not isinstance(condition, dict):
        raise PolicyParseError(f"Statement[{index}].Condition must be an object")

    return Statement(
        effect=effect_normalized,
        actions=tuple(actions),
        resources=tuple(resources),
        condition=condition,
        sid=sid,
    )


def _normalize_string_list(value: Any, field_name: str) -> list[str]:
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, list):
        items = value
    else:
        raise PolicyParseError(f"{field_name} must be a string or list")

    result: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise PolicyParseError(f"{field_name} items must be strings")
        if not item:
            raise PolicyParseError(f"{field_name} items cannot be empty")
        result.append(item)
    if not result:
        raise PolicyParseError(f"{field_name} must not be empty")
    return result


def _canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
