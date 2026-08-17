"""Shared result-evidence predicates for publication gates."""


def claims_synthetic(row):
    """Report whether a result row claims synthetic calibration evidence.

    An explicit boolean false is an honest negative and is honored. Every other
    present value counts as a claim, including a non-boolean such as
    ``"synthetic": "calibration"``. Requiring the boolean true would let a
    malformed marker make a run read as measured, which inverts the gate.
    """
    evidence = row.get("evidence")
    if not isinstance(evidence, dict) or "synthetic" not in evidence:
        return False
    return evidence["synthetic"] is not False
