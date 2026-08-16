"""Dependency-free JSON Schema validation for governed artifacts."""

import json
import math
import re
from datetime import date, datetime
from pathlib import Path


def load_schema(path):
    with Path(path).open(encoding="utf-8") as handle:
        schema = json.load(handle)
    if not isinstance(schema, dict):
        raise ValueError(f"schema must be an object: {path}")
    return schema


def validate(document, schema, label="artifact"):
    _validate(document, schema, schema, label)
    return document


def validate_file(document, schema_path, label="artifact"):
    return validate(document, load_schema(schema_path), label)


def _resolve(root, reference):
    if not reference.startswith("#/"):
        raise ValueError(f"unsupported schema reference: {reference}")
    value = root
    for token in reference[2:].split("/"):
        value = value[token.replace("~1", "/").replace("~0", "~")]
    return value


def _type_matches(value, expected):
    checks = {
        "object": lambda: isinstance(value, dict),
        "array": lambda: isinstance(value, list),
        "string": lambda: isinstance(value, str),
        "integer": lambda: isinstance(value, int) and not isinstance(value, bool),
        "number": lambda: isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": lambda: isinstance(value, bool),
        "null": lambda: value is None,
    }
    if expected not in checks:
        raise ValueError(f"unsupported schema type: {expected}")
    return checks[expected]()


def _validate(value, schema, root, path):
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{path} must be a finite JSON number")
    if "$ref" in schema:
        _validate(value, _resolve(root, schema["$ref"]), root, path)
        return
    if "const" in schema and value != schema["const"]:
        raise ValueError(f"{path} must equal {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path} must be one of {schema['enum']!r}")
    expected = schema.get("type")
    if expected is not None:
        choices = expected if isinstance(expected, list) else [expected]
        if not any(_type_matches(value, choice) for choice in choices):
            raise ValueError(f"{path} has the wrong JSON type")
    if value is None:
        return
    if isinstance(value, dict):
        missing = [name for name in schema.get("required", []) if name not in value]
        if missing:
            raise ValueError(f"{path} is missing required fields: {missing}")
        for trigger, dependencies in schema.get("dependentRequired", {}).items():
            if trigger not in value:
                continue
            missing_dependencies = [name for name in dependencies if name not in value]
            if missing_dependencies:
                raise ValueError(
                    f"{path} field {trigger!r} requires fields: {missing_dependencies}"
                )
        if len(value) < schema.get("minProperties", 0):
            raise ValueError(f"{path} has too few properties")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for name, child in value.items():
            child_schema = properties.get(name)
            if child_schema is None:
                if additional is False:
                    raise ValueError(f"{path} has unknown field {name!r}")
                if isinstance(additional, dict):
                    child_schema = additional
            if child_schema is not None:
                _validate(child, child_schema, root, f"{path}.{name}")
        if schema.get("propertyNames"):
            for name in value:
                _validate(name, schema["propertyNames"], root, f"{path} property name")
    elif isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise ValueError(f"{path} has too few items")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(encoded) != len(set(encoded)):
                raise ValueError(f"{path} items must be unique")
        if isinstance(schema.get("items"), dict):
            for index, child in enumerate(value):
                _validate(child, schema["items"], root, f"{path}[{index}]")
    elif isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise ValueError(f"{path} is too short")
        if schema.get("pattern") is not None and re.search(schema["pattern"], value) is None:
            raise ValueError(f"{path} does not match {schema['pattern']!r}")
        if schema.get("format") == "date":
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is None:
                raise ValueError(f"{path} must be an RFC 3339 date")
            try:
                date.fromisoformat(value)
            except ValueError as exc:
                raise ValueError(f"{path} must be an RFC 3339 date") from exc
        if schema.get("format") == "date-time":
            if re.fullmatch(
                r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})",
                value,
            ) is None:
                raise ValueError(f"{path} must be an RFC 3339 timestamp")
            try:
                normalized = value.replace("t", "T").replace("z", "Z").replace("Z", "+00:00")
                parsed = datetime.fromisoformat(normalized)
            except ValueError as exc:
                raise ValueError(f"{path} must be an RFC 3339 timestamp") from exc
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError(f"{path} timestamp must include a timezone")
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ValueError(f"{path} is below its minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise ValueError(f"{path} is above its maximum")
