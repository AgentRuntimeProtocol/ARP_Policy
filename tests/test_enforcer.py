from arp_policy import Enforcer, Policy


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
