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
