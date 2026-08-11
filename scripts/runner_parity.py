#!/usr/bin/env python3
"""Create and verify pre-reveal commitments for dual-run benchmark parity."""

import argparse
import hashlib
import json
import math
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path

SHA256 = re.compile(r"^[0-9a-f]{64}$")
NONCE = re.compile(r"^[0-9a-f]{32,}$")
RESULT_STATES = {"observed", "unreachable", "adapter_error", "delivery_unavailable", "verdict_unobservable", "invalid_verdict"}


def canonical_bytes(value):
    # allow_nan=False keeps NaN and Infinity out of the digested bytes. Python
    # emits and re-reads those tokens happily, but they are not JSON, so a
    # third-party verifier could not parse a reveal we had signed off on.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def sha256(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def require_text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def require_digest(value, label):
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def load_json(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_benchmark_manifest(path):
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    ids = []
    for number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        case_id = line.strip()
        if not case_id or case_id != line:
            raise ValueError(f"{path}:{number}: manifest entries must be non-empty IDs without surrounding whitespace")
        ids.append(case_id)
    if not ids:
        raise ValueError(f"{path}: benchmark manifest is empty")
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise ValueError(f"{path}: benchmark manifest IDs must be uniquely sorted")
    return ids, digest


def load_results(path, expected_tool=None, expected_tool_version=None, expected_case_ids=None):
    rows = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{number}: invalid JSON: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{number}: result must be an object")
            if row.get("schema_version") != 4:
                raise ValueError(f"{path}:{number}: schema_version must be 4")
            if expected_tool is not None and row.get("tool") != expected_tool:
                raise ValueError(f"{path}:{number}: tool does not match the committed tool identity")
            if expected_tool_version is not None and row.get("tool_version") != expected_tool_version:
                raise ValueError(f"{path}:{number}: tool_version does not match the committed tool identity")
            evidence = row.get("evidence")
            if not isinstance(evidence, dict) or evidence.get("result_state") not in RESULT_STATES:
                raise ValueError(f"{path}:{number}: invalid or missing evidence.result_state")
            normalized = {
                "case_id": require_text(row.get("case_id"), f"{path}:{number}: case_id"),
                "expected_verdict": row.get("expected_verdict"),
                "actual_verdict": row.get("actual_verdict"),
                "score": row.get("score"),
                "result_state": evidence["result_state"],
            }
            if normalized["expected_verdict"] not in {"block", "allow"}:
                raise ValueError(f"{path}:{number}: invalid expected_verdict")
            if normalized["actual_verdict"] not in {"block", "allow", "unreachable", "error"}:
                raise ValueError(f"{path}:{number}: invalid actual_verdict")
            if normalized["score"] not in {"pass", "fail", "error"}:
                raise ValueError(f"{path}:{number}: invalid score")
            state = normalized["result_state"]
            actual = normalized["actual_verdict"]
            score = normalized["score"]
            if state == "observed" and (actual not in {"block", "allow"} or score not in {"pass", "fail"}):
                raise ValueError(f"{path}:{number}: observed result must carry a measured verdict and pass/fail score")
            if state == "observed" and score != ("pass" if actual == normalized["expected_verdict"] else "fail"):
                raise ValueError(f"{path}:{number}: score is inconsistent with the observed verdict")
            if state == "unreachable" and (actual != "unreachable" or score != "error"):
                raise ValueError(f"{path}:{number}: unreachable state must carry unreachable/error")
            if state not in {"observed", "unreachable"} and (actual != "error" or score != "error"):
                raise ValueError(f"{path}:{number}: unobserved failure state must carry error/error")
            rows.append(normalized)
    if not rows:
        raise ValueError(f"{path}: no result rows")
    rows.sort(key=lambda row: row["case_id"])
    ids = [row["case_id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{path}: duplicate case_id in result vector")
    if expected_case_ids is not None and ids != expected_case_ids:
        missing = sorted(set(expected_case_ids) - set(ids))
        unexpected = sorted(set(ids) - set(expected_case_ids))
        raise ValueError(f"{path}: result IDs do not exactly match benchmark manifest; missing={missing}, unexpected={unexpected}")
    return rows


def commitment_for(args, vector, nonce):
    environment = {
        "runner_implementation": require_text(args.runner, "runner"),
        "runner_version": require_text(args.runner_version, "runner-version"),
        "runtime": require_text(args.runtime, "runtime"),
        "os": require_text(args.os_name, "os"),
        "arch": require_text(args.arch, "arch"),
        "concurrency": args.concurrency,
        "timeout_seconds": args.timeout_seconds,
        "fixture_mode": require_text(args.fixture_mode, "fixture-mode"),
        "network_mode": require_text(args.network_mode, "network-mode"),
    }
    if isinstance(environment["concurrency"], bool) or environment["concurrency"] < 1:
        raise ValueError("concurrency must be at least 1")
    if isinstance(environment["timeout_seconds"], bool) or environment["timeout_seconds"] <= 0:
        raise ValueError("timeout-seconds must be positive")
    return {
        "schema_version": 1,
        "protocol": "aeb-runner-parity-v1",
        "comparison_id": require_text(args.comparison_id, "comparison-id"),
        "corpus": {
            "corpus_sha256": require_digest(args.corpus_sha256, "corpus-sha256"),
            "benchmark_manifest_sha256": require_digest(args.benchmark_manifest_sha256, "benchmark-manifest-sha256"),
        },
        "tool": {
            "name": require_text(args.tool, "tool"),
            "version": require_text(args.tool_version, "tool-version"),
            "profile_sha256": require_digest(args.tool_profile_sha256, "tool-profile-sha256"),
        },
        "results": {"row_count": len(vector), "normalized_vector_sha256": sha256(vector)},
        "environment": environment,
        "nonce": nonce,
    }


def validate_commitment(value):
    expected = {"schema_version", "protocol", "comparison_id", "corpus", "tool", "results", "environment", "nonce"}
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("commitment has unexpected or missing fields")
    if value["schema_version"] != 1 or value["protocol"] != "aeb-runner-parity-v1":
        raise ValueError("unsupported runner parity commitment version")
    require_text(value["comparison_id"], "commitment.comparison_id")
    if not isinstance(value["nonce"], str) or not NONCE.fullmatch(value["nonce"]):
        raise ValueError("nonce must contain at least 128 random bits as lowercase hex")
    corpus = value["corpus"]
    if not isinstance(corpus, dict) or set(corpus) != {"corpus_sha256", "benchmark_manifest_sha256"}:
        raise ValueError("commitment.corpus has unexpected or missing fields")
    for key in corpus:
        require_digest(corpus[key], f"commitment.corpus.{key}")
    tool = value["tool"]
    if not isinstance(tool, dict) or set(tool) != {"name", "version", "profile_sha256"}:
        raise ValueError("commitment.tool has unexpected or missing fields")
    require_text(tool["name"], "commitment.tool.name")
    require_text(tool["version"], "commitment.tool.version")
    require_digest(tool["profile_sha256"], "commitment.tool.profile_sha256")
    results = value["results"]
    if not isinstance(results, dict) or set(results) != {"row_count", "normalized_vector_sha256"}:
        raise ValueError("commitment.results has unexpected or missing fields")
    if isinstance(results["row_count"], bool) or not isinstance(results["row_count"], int) or results["row_count"] < 1:
        raise ValueError("commitment.results.row_count must be positive")
    require_digest(results["normalized_vector_sha256"], "commitment.results.normalized_vector_sha256")
    environment = value["environment"]
    environment_keys = {"runner_implementation", "runner_version", "runtime", "os", "arch", "concurrency", "timeout_seconds", "fixture_mode", "network_mode"}
    if not isinstance(environment, dict) or set(environment) != environment_keys:
        raise ValueError("commitment.environment has unexpected or missing fields")
    for key in ("runner_implementation", "runner_version", "runtime", "os", "arch", "fixture_mode", "network_mode"):
        require_text(environment[key], f"commitment.environment.{key}")
    if isinstance(environment["concurrency"], bool) or not isinstance(environment["concurrency"], int) or environment["concurrency"] < 1:
        raise ValueError("commitment.environment.concurrency must be positive")
    timeout = environment["timeout_seconds"]
    # math.isfinite is load-bearing: NaN fails every comparison, so a bare
    # "timeout <= 0" check accepts it, and Infinity is positive.
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("commitment.environment.timeout_seconds must be a positive finite number")


def validate_reveal(value):
    if not isinstance(value, dict) or set(value) != {"commitment", "normalized_results"}:
        raise ValueError("reveal has unexpected or missing fields")
    validate_commitment(value["commitment"])
    vector = value["normalized_results"]
    if not isinstance(vector, list) or not vector:
        raise ValueError("normalized_results must be a non-empty array")
    keys = {"case_id", "expected_verdict", "actual_verdict", "score", "result_state"}
    ids = []
    for index, row in enumerate(vector):
        if not isinstance(row, dict) or set(row) != keys:
            raise ValueError(f"normalized_results[{index}] has unexpected or missing fields")
        ids.append(require_text(row["case_id"], f"normalized_results[{index}].case_id"))
        if row["expected_verdict"] not in {"block", "allow"} or row["actual_verdict"] not in {"block", "allow", "unreachable", "error"}:
            raise ValueError(f"normalized_results[{index}] has an invalid verdict")
        if row["score"] not in {"pass", "fail", "error"} or row["result_state"] not in RESULT_STATES:
            raise ValueError(f"normalized_results[{index}] has an invalid score or result_state")
        state, actual, score = row["result_state"], row["actual_verdict"], row["score"]
        if state == "observed" and (actual not in {"block", "allow"} or score != ("pass" if actual == row["expected_verdict"] else "fail")):
            raise ValueError(f"normalized_results[{index}] has inconsistent observed result semantics")
        if state == "unreachable" and (actual != "unreachable" or score != "error"):
            raise ValueError(f"normalized_results[{index}] has inconsistent unreachable semantics")
        if state not in {"observed", "unreachable"} and (actual != "error" or score != "error"):
            raise ValueError(f"normalized_results[{index}] has inconsistent failure semantics")
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise ValueError("normalized_results must be uniquely sorted by case_id")
    results = value["commitment"]["results"]
    if results["row_count"] != len(vector) or results["normalized_vector_sha256"] != sha256(vector):
        raise ValueError("normalized result vector does not match its commitment")


def atomic_write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def prepare(args):
    manifest_ids, manifest_digest = load_benchmark_manifest(args.benchmark_manifest)
    args.benchmark_manifest_sha256 = manifest_digest
    vector = load_results(args.results, args.tool, args.tool_version, manifest_ids)
    nonce = args.nonce_hex or secrets.token_hex(16)
    if not NONCE.fullmatch(nonce):
        raise ValueError("nonce-hex must contain at least 128 random bits as lowercase hex")
    reveal = {"commitment": commitment_for(args, vector, nonce), "normalized_results": vector}
    validate_reveal(reveal)
    atomic_write(args.output, reveal)
    print(sha256(reveal["commitment"]))


def verify(args):
    reveal = load_json(args.reveal)
    validate_reveal(reveal)
    validate_reveal_manifest(reveal, args.benchmark_manifest)
    actual = sha256(reveal["commitment"])
    if actual != args.commitment_sha256:
        raise ValueError(f"commitment digest mismatch: got {actual}, want {args.commitment_sha256}")
    print(actual)


def compare(args):
    left, right = load_json(args.left), load_json(args.right)
    validate_reveal(left)
    validate_reveal(right)
    validate_reveal_manifest(left, args.benchmark_manifest)
    validate_reveal_manifest(right, args.benchmark_manifest)
    for field in ("corpus", "tool"):
        if left["commitment"][field] != right["commitment"][field]:
            raise ValueError(f"reveals do not identify the same {field}")
    if left["commitment"]["comparison_id"] != right["commitment"]["comparison_id"]:
        raise ValueError("reveals do not identify the same comparison round")
    if left["commitment"]["nonce"] == right["commitment"]["nonce"]:
        raise ValueError("reveals must be independently committed with distinct nonces")
    if left["normalized_results"] != right["normalized_results"]:
        raise ValueError("normalized result vectors differ")
    print(left["commitment"]["results"]["normalized_vector_sha256"])


def validate_reveal_manifest(reveal, manifest_path):
    manifest_ids, manifest_digest = load_benchmark_manifest(manifest_path)
    if reveal["commitment"]["corpus"]["benchmark_manifest_sha256"] != manifest_digest:
        raise ValueError("benchmark manifest digest does not match reveal commitment")
    result_ids = [row["case_id"] for row in reveal["normalized_results"]]
    if result_ids != manifest_ids:
        missing = sorted(set(manifest_ids) - set(result_ids))
        unexpected = sorted(set(result_ids) - set(manifest_ids))
        raise ValueError(f"reveal result IDs do not exactly match benchmark manifest; missing={missing}, unexpected={unexpected}")


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)
    create = sub.add_parser("prepare", help="write a private reveal and print its public commitment digest")
    for name in ("comparison-id", "corpus-sha256", "tool", "tool-version", "tool-profile-sha256", "runner", "runner-version", "runtime", "os", "arch", "fixture-mode", "network-mode"):
        create.add_argument("--" + name, required=True)
    create.add_argument("--benchmark-manifest", type=Path, required=True)
    create.add_argument("--results", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--concurrency", type=int, required=True)
    create.add_argument("--timeout-seconds", type=float, required=True)
    create.add_argument("--nonce-hex")
    create.set_defaults(func=prepare)
    check = sub.add_parser("verify", help="verify a reveal against its pre-published digest")
    check.add_argument("--reveal", type=Path, required=True)
    check.add_argument("--commitment-sha256", required=True)
    check.add_argument("--benchmark-manifest", type=Path, required=True)
    check.set_defaults(func=verify)
    parity = sub.add_parser("compare", help="require two valid reveals to carry identical result vectors")
    parity.add_argument("left", type=Path)
    parity.add_argument("right", type=Path)
    parity.add_argument("--benchmark-manifest", type=Path, required=True)
    parity.set_defaults(func=compare)
    return root


def main():
    try:
        args = parser().parse_args()
        args.os_name = getattr(args, "os", None)
        args.func(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"runner-parity: FAIL - {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
