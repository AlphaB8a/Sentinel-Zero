#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys


STATE_INTAKE_MISSING_FIELD = "STATE_INTAKE_MISSING_FIELD"
STATE_INTAKE_SCHEMA_INVALID = "STATE_INTAKE_SCHEMA_INVALID"
STATE_INTAKE_AUTHORITY_AMBIGUOUS = "STATE_INTAKE_AUTHORITY_AMBIGUOUS"
STATE_INTAKE_POLICY_MISSING = "STATE_INTAKE_POLICY_MISSING"
STATE_INTAKE_EVIDENCE_POLICY_MISSING = "STATE_INTAKE_EVIDENCE_POLICY_MISSING"
STATE_INTAKE_REFERENCED_FILE_MISSING = "STATE_INTAKE_REFERENCED_FILE_MISSING"
STATE_INTAKE_QUARANTINE_EXPORT_VIOLATION = "STATE_INTAKE_QUARANTINE_EXPORT_VIOLATION"


def fail(code: str, message: str) -> None:
    print(f"[intake][FAIL][{code}] {message}")
    raise SystemExit(1)


def is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def path_str(path) -> str:
    if not path:
        return "$"
    return "$." + ".".join(path)


def validate_datetime(value: str, path):
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt.datetime.fromisoformat(value)
    except Exception:
        fail(STATE_INTAKE_SCHEMA_INVALID, f"{path_str(path)} must be RFC3339 date-time")


def required_missing_code(path, missing_key: str) -> str:
    if len(path) == 0:
        if missing_key == "lane_policy":
            return STATE_INTAKE_POLICY_MISSING
        if missing_key == "evidence_policy":
            return STATE_INTAKE_EVIDENCE_POLICY_MISSING
        if missing_key == "authority":
            return STATE_INTAKE_AUTHORITY_AMBIGUOUS
    return STATE_INTAKE_MISSING_FIELD


def validate(value, schema, path):
    if "const" in schema and value != schema["const"]:
        fail(STATE_INTAKE_SCHEMA_INVALID, f"{path_str(path)} must equal const={schema['const']!r}")

    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(value, dict):
            fail(STATE_INTAKE_SCHEMA_INVALID, f"{path_str(path)} must be an object")

        required = schema.get("required", [])
        for key in required:
            if key not in value:
                fail(required_missing_code(path, key), f"missing required field {path_str(path + [key])}")

        if schema.get("additionalProperties") is False:
            allowed = set(schema.get("properties", {}).keys())
            unknown = sorted(set(value.keys()) - allowed)
            if unknown:
                fail(STATE_INTAKE_SCHEMA_INVALID, f"unknown fields at {path_str(path)}: {unknown}")

        for key, subschema in schema.get("properties", {}).items():
            if key in value:
                validate(value[key], subschema, path + [key])

    elif expected_type == "array":
        if not isinstance(value, list):
            fail(STATE_INTAKE_SCHEMA_INVALID, f"{path_str(path)} must be an array")
        min_items = schema.get("minItems")
        if min_items is not None and len(value) < min_items:
            fail(STATE_INTAKE_SCHEMA_INVALID, f"{path_str(path)} must contain at least {min_items} item(s)")
        item_schema = schema.get("items")
        if item_schema is not None:
            for idx, item in enumerate(value):
                validate(item, item_schema, path + [str(idx)])

    elif expected_type == "string":
        if not isinstance(value, str):
            fail(STATE_INTAKE_SCHEMA_INVALID, f"{path_str(path)} must be a string")
        min_length = schema.get("minLength")
        if min_length is not None and len(value) < min_length:
            fail(STATE_INTAKE_SCHEMA_INVALID, f"{path_str(path)} must have minLength={min_length}")
        if schema.get("format") == "date-time":
            validate_datetime(value, path)

    elif expected_type == "boolean":
        if not isinstance(value, bool):
            fail(STATE_INTAKE_SCHEMA_INVALID, f"{path_str(path)} must be boolean")

    elif expected_type == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            fail(STATE_INTAKE_SCHEMA_INVALID, f"{path_str(path)} must be integer")
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if minimum is not None and value < minimum:
            fail(STATE_INTAKE_SCHEMA_INVALID, f"{path_str(path)} must be >= {minimum}")
        if maximum is not None and value > maximum:
            fail(STATE_INTAKE_SCHEMA_INVALID, f"{path_str(path)} must be <= {maximum}")

    elif expected_type == "number":
        if not is_number(value):
            fail(STATE_INTAKE_SCHEMA_INVALID, f"{path_str(path)} must be number")
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if minimum is not None and value < minimum:
            fail(STATE_INTAKE_SCHEMA_INVALID, f"{path_str(path)} must be >= {minimum}")
        if maximum is not None and value > maximum:
            fail(STATE_INTAKE_SCHEMA_INVALID, f"{path_str(path)} must be <= {maximum}")

    enum = schema.get("enum")
    if enum is not None and value not in enum:
        fail(STATE_INTAKE_SCHEMA_INVALID, f"{path_str(path)} must be one of {enum}")


def resolve_path(repo_root: Path, candidate: str) -> Path:
    path = Path(candidate)
    if path.is_absolute():
        return path
    return repo_root / path


def validate_referenced_files(contract: dict, repo_root: Path) -> None:
    refs = []
    refs.extend(contract["inputs"]["artifacts"].get("known_paths", []))
    refs.extend(contract["inputs"]["workorders"].get("paths", []))

    for rel in refs:
        resolved = resolve_path(repo_root, rel)
        if not resolved.exists():
            fail(STATE_INTAKE_REFERENCED_FILE_MISSING, f"referenced file missing: {rel} -> {resolved}")


def validate_policy_guards(contract: dict) -> None:
    authority = contract["authority"]
    if not any(
        [
            authority.get("local_first", False),
            authority.get("can_execute", False),
            authority.get("can_merge", False),
            authority.get("can_publish", False),
        ]
    ):
        fail(STATE_INTAKE_AUTHORITY_AMBIGUOUS, "authority booleans are all false")

    lane = contract["lane_policy"]["data_origin"]
    if lane.get("quarantine_allowed") and not lane.get("export_requires_verified_origin"):
        fail(
            STATE_INTAKE_QUARANTINE_EXPORT_VIOLATION,
            "quarantine is allowed but export is not restricted to verified origin",
        )


def load_json(path: Path, missing_code: str) -> dict:
    if not path.exists():
        fail(missing_code, f"file not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(STATE_INTAKE_SCHEMA_INVALID, f"invalid JSON in {path}: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fail-closed validator for state.intake.contract.v1")
    parser.add_argument(
        "--contract",
        default="DOCS/CONTRACTS/STATE_INTAKE_CURRENT_v1.json",
        help="Path to intake contract JSON",
    )
    parser.add_argument(
        "--schema",
        default="CONTRACTS/schemas/state_intake_contract_v1.schema.json",
        help="Path to intake schema JSON",
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root used for resolving referenced relative paths",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    contract_path = Path(args.contract)
    if not contract_path.is_absolute():
        contract_path = (repo_root / contract_path).resolve()
    schema_path = Path(args.schema)
    if not schema_path.is_absolute():
        schema_path = (repo_root / schema_path).resolve()

    contract = load_json(contract_path, STATE_INTAKE_MISSING_FIELD)
    schema = load_json(schema_path, STATE_INTAKE_SCHEMA_INVALID)

    validate(contract, schema, [])
    validate_policy_guards(contract)
    validate_referenced_files(contract, repo_root)

    canonical = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
    contract_sha256 = hashlib.sha256(canonical).hexdigest()
    print(
        "[intake][PASS] "
        f"schema={schema.get('$id', 'unknown')} "
        f"contract={contract_path} "
        f"contract_sha256={contract_sha256}"
    )


if __name__ == "__main__":
    main()
