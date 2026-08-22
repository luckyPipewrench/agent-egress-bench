#!/usr/bin/env python3
"""Keep public cross-field contracts aligned with schemas and owner docs."""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runner_parity  # noqa: E402  (path set above so the sibling module resolves)


BACKTICK_VALUE = re.compile(r"`([^`]+)`")


def fail(message):
    raise ValueError(message)


def load_json(path):
    raw = path.read_bytes()
    if not raw.strip():
        fail(f"empty JSON input: {path}")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: {exc}")


def schema_property(schema, name):
    value = schema.get("properties", {}).get(name)
    if not isinstance(value, dict):
        fail(f"schema property {name!r} is missing")
    return value


def markdown_table(document, marker):
    if marker not in document:
        fail(f"missing documentation heading {marker!r}")
    section = document.split(marker, 1)[1]
    rows = []
    started = False
    for line in section.splitlines():
        if not line.startswith("|"):
            if started:
                break
            continue
        started = True
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if all(set(cell) <= {"-", ":"} for cell in cells):
            continue
        rows.append(cells)
    if len(rows) < 2:
        fail(f"documentation table under {marker!r} is empty")
    return rows[0], rows[1:]


def backtick_values(cell):
    values = BACKTICK_VALUE.findall(cell)
    if not values:
        fail(f"table cell has no backtick value: {cell!r}")
    return values


def check_case_shapes(root):
    contract = load_json(root / "contracts/case-shapes-v4.json")
    schema = load_json(root / "schemas/case-v4.schema.json")
    multi_schema = load_json(root / "schemas/multi-file-case-v4.schema.json")
    if (contract.get("contract"), contract.get("format"), contract.get("case_schema_version")) != (
        "aeb.case-shapes",
        1,
        4,
    ):
        fail("case-shapes identity or version is invalid")
    single = contract.get("single_file")
    multi = contract.get("multi_file")
    if not isinstance(single, dict) or not single or not isinstance(multi, dict) or set(multi) != {"mcp_drift"}:
        fail("case-shapes must contain non-empty single_file and exactly one mcp_drift multi_file shape")
    if set(schema_property(schema, "category").get("enum", [])) != set(single):
        fail("case schema category enum differs from case-shapes single_file categories")
    input_types = {value for shape in single.values() for value in shape.get("input_types", [])}
    transports = {value for shape in single.values() for value in shape.get("transports", [])}
    if set(schema_property(schema, "input_type").get("enum", [])) != input_types:
        fail("case schema input_type enum differs from case-shapes values")
    if set(schema_property(schema, "transport").get("enum", [])) != transports:
        fail("case schema transport enum differs from case-shapes values")
    if set(schema_property(schema, "expected_verdict").get("enum", [])) != {"allow", "block", "warn"}:
        fail("single-file case schema must preserve the schema-v4 allow/block/warn vocabulary")
    drift = multi["mcp_drift"]
    if schema_property(multi_schema, "category").get("const") != "mcp_drift":
        fail("multi-file schema category differs from case-shapes")
    if schema_property(multi_schema, "input_type").get("const") not in drift.get("input_types", []):
        fail("multi-file schema input_type differs from case-shapes")
    if set(schema_property(multi_schema, "transport").get("enum", [])) != set(drift.get("transports", [])):
        fail("multi-file schema transports differ from case-shapes")

    header, rows = markdown_table(
        (root / "docs/SPEC.md").read_text(),
        "### Valid category, input, and transport combinations",
    )
    if header != ["Category", "Allowed input types", "Allowed transports"]:
        fail(f"SPEC case-shape table header changed: {header}")
    documented = {}
    for row in rows:
        if len(row) != 3:
            fail(f"SPEC case-shape row has {len(row)} cells: {row}")
        category = backtick_values(row[0])[0]
        documented[category] = {
            "input_types": sorted(backtick_values(row[1])),
            "transports": sorted(backtick_values(row[2])),
        }
    expected = {name: {key: sorted(values) for key, values in shape.items()} for name, shape in single.items()}
    expected.update({name: {key: sorted(values) for key, values in shape.items()} for name, shape in multi.items()})
    if documented != expected:
        fail("SPEC case-shape table differs from contracts/case-shapes-v4.json")


def check_result_states(root):
    contract = load_json(root / "contracts/result-states-v6.json")
    schema = load_json(root / "schemas/result-v6.schema.json")
    if (contract.get("contract"), contract.get("format"), contract.get("result_schema_version"), contract.get("scoring_version")) != (
        "aeb.result-states",
        1,
        6,
        runner_parity.SCORING_VERSION,
    ):
        fail("result-states identity or version is invalid")
    if runner_parity.RESULT_SCHEMA_VERSION != contract["result_schema_version"]:
        fail("parity reader result schema version differs from result-states")
    scoring_property = schema_property(schema, "scoring_version")
    if scoring_property.get("type") != "string" or scoring_property.get("minLength", 0) < 1:
        fail("result schema scoring_version must require a non-empty string")
    for field, schema_field in (
        ("expected_verdicts", "expected_verdict"),
        ("actual_verdicts", "actual_verdict"),
        ("scores", "score"),
    ):
        if set(contract.get(field, [])) != set(schema_property(schema, schema_field).get("enum", [])):
            fail(f"result schema {schema_field} enum differs from result-states {field}")
    # evidence.result_state is emitted on every row and consumed by the schema,
    # Go validator, and parity reader. Bind the published vocabulary to every
    # machine-readable surface so one reader cannot silently accept a state
    # another rejects.
    published_states = contract.get("evidence_result_states")
    if not isinstance(published_states, dict) or not published_states:
        fail("result-states must publish a non-empty evidence_result_states object")
    for name, meaning in published_states.items():
        if not isinstance(meaning, str) or not meaning.strip():
            fail(f"evidence_result_states.{name} must document what the state means")
    if set(published_states) != set(runner_parity.RESULT_STATES):
        missing = sorted(set(runner_parity.RESULT_STATES) - set(published_states))
        extra = sorted(set(published_states) - set(runner_parity.RESULT_STATES))
        fail(
            "evidence_result_states differs from the parity reader's RESULT_STATES; "
            f"unpublished={missing}, unenforced={extra}"
        )
    evidence = schema_property(schema, "evidence")
    if "result_state" not in evidence.get("required", []):
        fail("result schema evidence must require result_state")
    if set(schema_property(evidence, "result_state").get("enum", [])) != set(published_states):
        fail("result schema evidence.result_state enum differs from result-states")

    matrix = contract.get("matrix")
    if not isinstance(matrix, list):
        fail("result-states matrix must be an array")
    rows = {
        (row.get("expected_verdict"), row.get("actual_verdict"), row.get("score"))
        for row in matrix
        if isinstance(row, dict)
    }
    expected_pairs = {
        (expected, actual)
        for expected in contract["expected_verdicts"]
        for actual in contract["actual_verdicts"]
    }
    if len(rows) != len(matrix) or {(expected, actual) for expected, actual, _ in rows} != expected_pairs:
        fail("result-states matrix must cover each expected/actual pair exactly once")
    allowed = {
        ("allow", "allow", "pass"),
        ("allow", "block", "fail"),
        ("allow", "error", "error"),
        ("allow", "unreachable", "error"),
        ("block", "allow", "fail"),
        ("block", "block", "pass"),
        ("block", "error", "error"),
        ("block", "unreachable", "error"),
    }
    if rows != allowed:
        fail("result-states matrix has an invalid score binding")

    overrides = contract.get("case_specific_overrides")
    expected_override = {
        "name": "budget_block_timing",
        "when": {
            "expected_verdict": "block",
            "actual_verdict": "block",
            "case_payload_fields": ["budget_limit_calls"],
            "required_evidence_fields": ["budget_block_timing"],
        },
        "scores_by_budget_block_timing": {
            "at_over_budget": "pass",
            "before_over_budget": "fail",
            "after_over_budget": "fail",
        },
    }
    if (
        not isinstance(overrides, list)
        or len(overrides) != 1
        or overrides[0] != expected_override
    ):
        fail("result-states budget timing override is invalid")
    adapter_states = contract.get("adapter_only_states")
    if not isinstance(adapter_states, dict) or set(adapter_states) != {"skip"}:
        fail("result-states adapter-only states must contain exactly skip")
    if adapter_states["skip"].get("active_result") != {"actual_verdict": "error", "score": "error"}:
        fail("result-states skip must map to active error/error")
    historical_states = contract.get("historical_only_states")
    if (
        not isinstance(historical_states, dict)
        or set(historical_states) != {"not_applicable"}
        or not isinstance(historical_states["not_applicable"], str)
        or not historical_states["not_applicable"].strip()
    ):
        fail("result-states historical-only states must contain a not_applicable explanation")

    header, doc_rows = markdown_table((root / "docs/gauntlet.md").read_text(), "## Per-case results")
    if header != ["Expected verdict", "Actual verdict", "Score", "Meaning"]:
        fail(f"gauntlet result-state table header changed: {header}")
    documented = set()
    for row in doc_rows:
        if len(row) != 4:
            fail(f"gauntlet result-state row has {len(row)} cells: {row}")
        documented.add((backtick_values(row[0])[0], backtick_values(row[1])[0], backtick_values(row[2])[0]))
    if documented != rows:
        fail("gauntlet result-state table differs from contracts/result-states-v6.json")


def check(root):
    check_case_shapes(root)
    check_result_states(root)
    governance = (root / "docs/GOVERNANCE.md").read_text()
    required = (
        "relationship metadata, not a loader instruction",
        "runner executes both cases",
        "No mutable skip list",
    )
    for text in required:
        if text not in governance:
            fail(f"GOVERNANCE supersession contract is missing {text!r}")


def main():
    root = Path(__file__).resolve().parents[1]
    try:
        check(root)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"check-public-contracts: FAIL - {exc}", file=sys.stderr)
        return 1
    print("check-public-contracts: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
