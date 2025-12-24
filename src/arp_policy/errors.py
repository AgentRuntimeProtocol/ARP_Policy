class PolicyError(Exception):
    """Base error for arp-policy."""


class PolicyParseError(PolicyError):
    """Raised when a policy file cannot be parsed or validated."""


class PolicyEvaluationError(PolicyError):
    """Raised when policy evaluation fails due to invalid input."""
