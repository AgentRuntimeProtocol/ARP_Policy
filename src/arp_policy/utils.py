from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any, Mapping


def match_pattern(value: str, pattern: str) -> bool:
    return fnmatchcase(value, pattern)


def resolve_context_value(context: Mapping[str, Any], key: str) -> Any:
    if key in context:
        return context[key]
    if "." not in key:
        return None

    # First try nested traversal (context as nested dict).
    current: Any = context
    for part in key.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            current = None
            break
    if current is not None:
        return current

    # Fallback: treat prefix as a flat key, then traverse the remainder.
    parts = key.split(".")
    for i in range(len(parts) - 1, 0, -1):
        prefix = ".".join(parts[:i])
        if prefix not in context:
            continue
        current = context[prefix]
        for part in parts[i:]:
            if isinstance(current, Mapping) and part in current:
                current = current[part]
            else:
                return None
        return current

    return None
