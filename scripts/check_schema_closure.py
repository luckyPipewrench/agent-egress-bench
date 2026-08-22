#!/usr/bin/env python3
"""Reject ungoverned open object shapes in every published schema."""

import json
from pathlib import Path

try:
    from scripts import schema_catalog
except ModuleNotFoundError:
    import schema_catalog


ROOT = Path(__file__).resolve().parents[1]

# These are compatibility or extension points, not omissions. Dynamic maps
# with a schema-valued additionalProperties are closed over their values and
# do not need an exception.
OPEN_OBJECTS = {
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/case-v4.schema.json", "/properties/payload"): "payload shape is selected by input_type and checked by the case validator",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/control-evidence-manifest-v0.schema.json", "/properties/entries/allOf/0/contains"): "contains is a partial predicate over a closed entry",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/control-evidence-manifest-v0.schema.json", "/properties/entries/allOf/1/contains"): "contains is a partial predicate over a closed entry",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/control-evidence-manifest-v0.schema.json", "/properties/entries/allOf/2/contains"): "contains is a partial predicate over a closed entry",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/control-evidence-manifest-v1.schema.json", "/properties/entries/allOf/0/contains"): "contains is a partial predicate over a closed entry",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/control-evidence-manifest-v1.schema.json", "/properties/entries/allOf/1/contains"): "contains is a partial predicate over a closed entry",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/control-evidence-manifest-v1.schema.json", "/properties/entries/allOf/2/contains"): "contains is a partial predicate over a closed entry",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/provenance-candidate-v1.schema.json", "/properties/case_count"): "frozen historical shape",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/provenance-candidate-v1.schema.json", "/properties/scores"): "frozen historical shape",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/provenance-candidate-v1.schema.json", "/properties/metric_counts"): "frozen historical shape",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/provenance-candidate-v2.schema.json", "/properties/case_count"): "frozen historical shape",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/provenance-candidate-v2.schema.json", "/properties/scores"): "frozen historical shape",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/provenance-candidate-v2.schema.json", "/properties/metric_counts"): "frozen historical shape",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/provenance-candidate-v4.schema.json", "/properties/case_count"): "supported legacy reader shape with semantic checks",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/provenance-candidate-v4.schema.json", "/properties/scores"): "supported legacy reader shape with semantic checks",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/provenance-candidate-v4.schema.json", "/properties/metric_counts"): "supported legacy reader shape with semantic checks",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/provenance-candidate-v4.schema.json", "/properties/capability_registry"): "supported legacy reader shape with semantic checks",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/provenance-candidate-v4.schema.json", "/properties/exercised"): "supported legacy reader shape with semantic checks",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/result-v4.schema.json", "/properties/evidence"): "frozen evidence extension point",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/result-v5.schema.json", "/properties/evidence"): "frozen adapter evidence extension point with required result_state",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/result-v6.schema.json", "/properties/evidence"): "active adapter evidence extension point with required result_state",
    ("https://github.com/luckyPipewrench/agent-egress-bench/schemas/summary-v4.schema.json", ""): "frozen historical root",
}


def open_objects(document):
    found = set()

    object_keywords = {
        "properties",
        "required",
        "propertyNames",
        "additionalProperties",
        "dependentRequired",
        "minProperties",
        "maxProperties",
        "patternProperties",
    }

    same_instance_keywords = {"allOf", "anyOf", "oneOf", "not", "if", "then", "else", "dependentSchemas"}

    def walk(value, pointer="", inherited_closed=False, predicate_context=False):
        if isinstance(value, dict):
            declared_type = value.get("type")
            object_capable = declared_type == "object" or (
                isinstance(declared_type, list) and "object" in declared_type
            ) or bool(object_keywords & value.keys())
            closes_here = value.get("additionalProperties") is False or isinstance(
                value.get("additionalProperties"), dict
            )
            if object_capable:
                additional = value.get("additionalProperties", True)
                explicit_object = declared_type == "object" or (
                    isinstance(declared_type, list) and "object" in declared_type
                )
                if not inherited_closed and not (predicate_context and not explicit_object) and additional is not False and not isinstance(additional, dict):
                    found.add((document["$id"], pointer))
            for key, child in value.items():
                escaped = key.replace("~", "~0").replace("/", "~1")
                child_inherits = (inherited_closed or closes_here) if key in same_instance_keywords else False
                child_predicate = predicate_context or key in {"if", "then", "else", "not", "contains"}
                walk(child, pointer + "/" + escaped, child_inherits, child_predicate)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, pointer + f"/{index}", inherited_closed, predicate_context)

    walk(document)
    return found


def check(root=ROOT):
    found = set()
    for entry in schema_catalog.schema_entries(root):
        path = root / entry["path"]
        document = json.loads(path.read_text(encoding="utf-8"))
        found.update(open_objects(document))
    unexpected = sorted(found - set(OPEN_OBJECTS))
    stale = sorted(set(OPEN_OBJECTS) - found)
    if unexpected:
        raise ValueError(f"published schemas contain ungoverned open objects: {unexpected}")
    if stale:
        raise ValueError(f"open-object exception list is stale: {stale}")
    print(f"schema closure: OK ({len(found)} governed open object paths)")


if __name__ == "__main__":
    check()
