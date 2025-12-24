import hashlib
import json

import pytest

from arp_policy import Policy, PolicyParseError


def test_load_policy_normalizes_action_and_resource():
    data = {
        "Version": "2025-01-01",
        "Statement": {
            "Effect": "Allow",
            "Action": "tool:Invoke",
            "Resource": ["tool:finance/*"],
        },
    }

    policy = Policy.load(data)
    assert policy.version == "2025-01-01"
    assert len(policy.statements) == 1
    statement = policy.statements[0]
    assert statement.actions == ("tool:Invoke",)
    assert statement.resources == ("tool:finance/*",)


def test_load_policy_rejects_invalid_effect():
    data = {
        "Statement": {
            "Effect": "Block",
            "Action": "tool:Invoke",
            "Resource": "tool:*",
        }
    }

    with pytest.raises(PolicyParseError):
        Policy.load(data)


def test_load_policy_from_path_and_hash(tmp_path):
    data = {
        "Version": "2025-01-01",
        "Statement": {
            "Effect": "Allow",
            "Action": "tool:Invoke",
            "Resource": "tool:*",
            "statement_id": "allow-all",
        },
    }
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    policy = Policy.load(path)
    assert policy.version == "2025-01-01"
    assert policy.statements[0].sid == "allow-all"

    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    expected_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert policy.policy_hash == expected_hash


def test_load_policy_rejects_invalid_json(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(PolicyParseError):
        Policy.load(path)


def test_load_policy_rejects_invalid_input_type():
    with pytest.raises(PolicyParseError):
        Policy.load(123)  # type: ignore[arg-type]


def test_load_policy_requires_statement():
    with pytest.raises(PolicyParseError):
        Policy.load({"Version": "2025-01-01"})


def test_load_policy_statement_must_be_object_or_list():
    with pytest.raises(PolicyParseError):
        Policy.load({"Statement": "not-a-statement"})


def test_load_policy_statement_list_items_must_be_objects():
    with pytest.raises(PolicyParseError):
        Policy.load({"Statement": ["not-a-statement"]})


def test_parse_statement_normalizes_effect_and_sid():
    policy = Policy.load(
        {
            "Statement": {
                "Effect": " allow ",
                "Action": "tool:Invoke",
                "Resource": "tool:*",
                "statement_id": "statement-1",
            }
        }
    )
    statement = policy.statements[0]
    assert statement.effect == "Allow"
    assert statement.sid == "statement-1"


def test_parse_statement_requires_string_effect():
    with pytest.raises(PolicyParseError):
        Policy.load(
            {
                "Statement": {
                    "Effect": None,
                    "Action": "tool:Invoke",
                    "Resource": "tool:*",
                }
            }
        )


def test_parse_statement_requires_condition_object():
    with pytest.raises(PolicyParseError):
        Policy.load(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Action": "tool:Invoke",
                    "Resource": "tool:*",
                    "Condition": "nope",
                }
            }
        )


@pytest.mark.parametrize("action", [123, [], [""], [1]])
def test_normalize_string_list_validation(action):
    with pytest.raises(PolicyParseError):
        Policy.load(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Action": action,
                    "Resource": "tool:*",
                }
            }
        )


def test_from_dict_rejects_non_dict():
    with pytest.raises(PolicyParseError):
        Policy._from_dict("not-a-dict")  # type: ignore[arg-type]
