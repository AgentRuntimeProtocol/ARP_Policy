import pytest

from arp_policy import Enforcer, Policy, PolicyEvaluationError


def test_authorize_allow():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Sid": "AllowFinance",
                    "Effect": "Allow",
                    "Action": ["tool:Invoke"],
                    "Resource": ["tool:finance/*"],
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    decision = enforcer.authorize("tool:Invoke", "tool:finance/pay", {})
    assert decision.allowed is True
    assert decision.matched_statement_id == "AllowFinance"


def test_authorize_deny_overrides_allow():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Sid": "AllowAll",
                    "Effect": "Allow",
                    "Action": "tool:Invoke",
                    "Resource": "tool:*",
                },
                {
                    "Sid": "DenySecrets",
                    "Effect": "Deny",
                    "Action": "tool:Invoke",
                    "Resource": "tool:secrets/*",
                },
            ]
        }
    )
    enforcer = Enforcer(policy)

    decision = enforcer.authorize("tool:Invoke", "tool:secrets/read", {})
    assert decision.allowed is False
    assert decision.matched_statement_id == "DenySecrets"


def test_default_deny():
    policy = Policy.load({"Statement": []})
    enforcer = Enforcer(policy)

    decision = enforcer.authorize("tool:Invoke", "tool:any", {})
    assert decision.allowed is False
    assert decision.reason == "default_deny"


def test_condition_string_equals():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Sid": "AllowAlice",
                    "Effect": "Allow",
                    "Action": "tool:Invoke",
                    "Resource": "tool:*",
                    "Condition": {"StringEquals": {"principal": "alice"}},
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    decision = enforcer.authorize(
        "tool:Invoke",
        "tool:any",
        {"principal": "alice"},
    )
    assert decision.allowed is True


def test_condition_string_like():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Sid": "AllowEnv",
                    "Effect": "Allow",
                    "Action": "tool:Discover",
                    "Resource": "tool:*",
                    "Condition": {"StringLike": {"environment": "dev*"}},
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    decision = enforcer.authorize(
        "tool:Discover",
        "tool:any",
        {"environment": "dev"},
    )
    assert decision.allowed is True


def test_filter_tools():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Sid": "AllowTool",
                    "Effect": "Allow",
                    "Action": "tool:Discover",
                    "Resource": "tool:allowed",
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    tools = [
        {"tool_id": "allowed"},
        {"tool_id": "denied"},
    ]

    allowed = enforcer.filter_tools(tools, {})
    assert [tool["tool_id"] for tool in allowed] == ["allowed"]


def test_authorize_rejects_invalid_inputs():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "tool:Invoke",
                    "Resource": "tool:*",
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    with pytest.raises(PolicyEvaluationError):
        enforcer.authorize("", "tool:any", {})
    with pytest.raises(PolicyEvaluationError):
        enforcer.authorize("tool:Invoke", "", {})
    with pytest.raises(PolicyEvaluationError):
        enforcer.authorize(123, "tool:any", {})  # type: ignore[arg-type]


def test_enforcer_policy_property():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "tool:Invoke",
                    "Resource": "tool:*",
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    assert enforcer.policy is policy


def test_authorize_rejects_unsupported_condition_operator():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "tool:Invoke",
                    "Resource": "tool:*",
                    "Condition": {"NumericEquals": {"tenant": "acme"}},
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    with pytest.raises(PolicyEvaluationError):
        enforcer.authorize("tool:Invoke", "tool:any", {"tenant": "acme"})


@pytest.mark.parametrize(
    "condition",
    [
        {"StringEquals": "not-a-map"},
        {"StringLike": 123},
    ],
)
def test_authorize_rejects_invalid_condition_shape(condition):
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "tool:Invoke",
                    "Resource": "tool:*",
                    "Condition": condition,
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    with pytest.raises(PolicyEvaluationError):
        enforcer.authorize("tool:Invoke", "tool:any", {"tenant": "acme"})


def test_authorize_missing_context_falls_back_to_default_deny():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "tool:Invoke",
                    "Resource": "tool:*",
                    "Condition": {"StringLike": {"environment": "dev*"}},
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    decision = enforcer.authorize("tool:Invoke", "tool:any", {})
    assert decision.allowed is False
    assert decision.reason == "default_deny"


def test_authorize_string_equals_missing_context_denies():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "tool:Invoke",
                    "Resource": "tool:*",
                    "Condition": {"StringEquals": {"principal": "alice"}},
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    decision = enforcer.authorize("tool:Invoke", "tool:any", {})
    assert decision.allowed is False


def test_authorize_string_like_mismatch_denies():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "tool:Invoke",
                    "Resource": "tool:*",
                    "Condition": {"StringLike": {"environment": "dev*"}},
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    decision = enforcer.authorize("tool:Invoke", "tool:any", {"environment": "prod"})
    assert decision.allowed is False


def test_authorize_condition_values_skip_none():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "tool:Invoke",
                    "Resource": "tool:*",
                    "Condition": {"StringEquals": {"groups": ["admin"]}},
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    decision = enforcer.authorize("tool:Invoke", "tool:any", {"groups": [None]})
    assert decision.allowed is False


def test_authorize_coerces_values_and_includes_request_id():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "tool:Invoke",
                    "Resource": "tool:*",
                    "Condition": {
                        "StringEquals": {
                            "flag": "true",
                            "tenant": ["acme", "beta"],
                        }
                    },
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    decision = enforcer.authorize(
        "tool:Invoke",
        "tool:any",
        {"flag": True, "tenant": "beta", "request_id": 123},
    )
    assert decision.allowed is True
    assert decision.request_id == "123"


def test_authorize_rejects_object_condition_values():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "tool:Invoke",
                    "Resource": "tool:*",
                    "Condition": {"StringEquals": {"flag": {"bad": "value"}}},
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    with pytest.raises(PolicyEvaluationError):
        enforcer.authorize("tool:Invoke", "tool:any", {"flag": "true"})


def test_filter_tools_rejects_missing_tool_id():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "tool:Discover",
                    "Resource": "tool:*",
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    with pytest.raises(PolicyEvaluationError):
        enforcer.filter_tools([{"name": "missing"}], {})


def test_authorize_resource_mismatch_denies():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "tool:Invoke",
                    "Resource": "tool:allowed",
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    decision = enforcer.authorize("tool:Invoke", "tool:other", {})
    assert decision.allowed is False


def test_authorize_action_mismatch_denies():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "tool:Invoke",
                    "Resource": "tool:*",
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    decision = enforcer.authorize("tool:Discover", "tool:any", {})
    assert decision.allowed is False


def test_filter_tools_uses_tags_from_mapping():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "tool:Discover",
                    "Resource": "tool:*",
                    "Condition": {
                        "StringEquals": {
                            "tool.tags.tier": "gold",
                            "tool.tags.env": "prod",
                            "tool.tags.region": "us",
                        }
                    },
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    tools = [
        {
            "tool_id": "alpha",
            "metadata": {"labels": {"tier": "gold"}, "annotations": {"env": "prod"}},
            "tags": {"region": "us"},
        },
        {
            "tool_id": "beta",
            "metadata": {"labels": {"tier": "gold"}, "annotations": {"env": "dev"}},
            "tags": {"region": "us"},
        },
    ]

    allowed = enforcer.filter_tools(tools, {})
    assert [tool["tool_id"] for tool in allowed] == ["alpha"]


class _Meta:
    def __init__(self, labels, annotations):
        self.labels = labels
        self.annotations = annotations


class _Tool:
    def __init__(self, tool_id, metadata):
        self.tool_id = tool_id
        self.metadata = metadata


def test_filter_tools_supports_object_tools():
    policy = Policy.load(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "tool:Discover",
                    "Resource": "tool:*",
                    "Condition": {
                        "StringEquals": {
                            "tool.tags.tier": "gold",
                            "tool.tags.env": "prod",
                        }
                    },
                }
            ]
        }
    )
    enforcer = Enforcer(policy)

    tools = [
        _Tool("alpha", _Meta({"tier": "gold"}, {"env": "prod"})),
        _Tool("beta", _Meta({"tier": "silver"}, {"env": "prod"})),
    ]

    allowed = enforcer.filter_tools(tools, {})
    assert [tool.tool_id for tool in allowed] == ["alpha"]
