#!/usr/bin/env python3
"""CSV to JSON Dataset Converter.

Converts flow-feature and metadata CSV files into clean, standard JSON arrays
of objects while preserving data types (integers, floats, strings, nulls)
and column structure.
"""

import argparse
import csv
import json
import math
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple, Union


def parse_value(val: Optional[str]) -> Any:
    """Parse string representation of CSV cell into appropriate Python type.

    Rules:
    - Empty strings or None -> None (JSON null)
    - Integers -> int
    - Floats (including scientific notation) -> float
    - Special float strings ('nan', 'inf') -> preserved as strings
    - Other strings -> str
    """
    if val is None or val == "":
        return None

    val_stripped = val.strip()
    if val_stripped == "":
        return None

    # Check for integer
    if val_stripped.isdigit() or (
        val_stripped.startswith(("-", "+")) and val_stripped[1:].isdigit()
    ):
        try:
            return int(val_stripped)
        except ValueError:
            pass

    # Avoid converting 'nan', 'inf', 'infinity' strings into float NaN/Inf
    if val_stripped.lower() in (
        "nan",
        "inf",
        "-inf",
        "+inf",
        "infinity",
        "-infinity",
        "+infinity",
    ):
        return val

    # Check for float
    try:
        f_val = float(val_stripped)
        if not math.isnan(f_val) and not math.isinf(f_val):
            return f_val
    except ValueError:
        pass

    return val


def read_csv_to_records(csv_path: Union[str, Path]) -> Tuple[List[str], List[Dict[str, Any]]]:
    """Read a CSV file and convert rows to typed dictionaries.

    Returns:
        Tuple of (columns, list_of_records)
    """
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Input CSV file not found: {path}")

    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            # Completely empty file
            return [], []

        columns = [col.strip() for col in header]
        records: List[Dict[str, Any]] = []

        for row in reader:
            if not row or (len(row) == 1 and row[0].strip() == ""):
                continue
            record: Dict[str, Any] = {}
            for i, col in enumerate(columns):
                raw_val = row[i] if i < len(row) else ""
                record[col] = parse_value(raw_val)
            records.append(record)

    return columns, records


def convert_csv_to_json(
    csv_path: Union[str, Path],
    json_path: Union[str, Path],
    indent: int = 2,
) -> Dict[str, Any]:
    """Convert CSV file to JSON array-of-objects format.

    Returns summary dictionary with conversion statistics.
    """
    input_file = Path(csv_path)
    output_file = Path(json_path)

    columns, records = read_csv_to_records(input_file)

    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(records, f, indent=indent)
        f.write("\n")

    return {
        "input_csv": str(input_file),
        "output_json": str(output_file),
        "columns": columns,
        "column_count": len(columns),
        "row_count": len(records),
    }


def validate_conversion(
    csv_path: Union[str, Path],
    json_path: Union[str, Path],
    float_tolerance: float = 1e-6,
) -> Tuple[bool, List[str]]:
    """Validate JSON against CSV for row count, keys, and values."""
    errors: List[str] = []
    csv_file = Path(csv_path)
    json_file = Path(json_path)

    if not csv_file.exists():
        return False, [f"CSV file does not exist: {csv_file}"]
    if not json_file.exists():
        return False, [f"JSON file does not exist: {json_file}"]

    columns, expected_records = read_csv_to_records(csv_file)

    try:
        with json_file.open("r", encoding="utf-8") as f:
            json_data = json.load(f)
    except Exception as e:
        return False, [f"Failed to parse JSON file {json_file}: {e}"]

    if not isinstance(json_data, list):
        return False, [f"JSON root must be a list (array), found {type(json_data).__name__}"]

    if len(expected_records) != len(json_data):
        errors.append(
            f"Row count mismatch: CSV has {len(expected_records)} rows, JSON has {len(json_data)} objects"
        )

    for row_idx, (exp, act) in enumerate(zip(expected_records, json_data)):
        if not isinstance(act, dict):
            errors.append(f"Row {row_idx}: JSON element is not an object ({type(act).__name__})")
            continue

        exp_keys = list(exp.keys())
        act_keys = list(act.keys())

        if exp_keys != act_keys:
            errors.append(f"Row {row_idx}: Keys mismatch. Expected {exp_keys}, got {act_keys}")

        for key in exp_keys:
            exp_val = exp[key]
            act_val = act.get(key)

            if exp_val is None:
                if act_val is not None:
                    errors.append(
                        f"Row {row_idx}, key '{key}': Expected null, got {act_val!r}"
                    )
            elif isinstance(exp_val, float):
                if not isinstance(act_val, (float, int)):
                    errors.append(
                        f"Row {row_idx}, key '{key}': Expected float/number, got {type(act_val).__name__} ({act_val!r})"
                    )
                else:
                    if not math.isclose(exp_val, float(act_val), rel_tol=float_tolerance, abs_tol=float_tolerance):
                        errors.append(
                            f"Row {row_idx}, key '{key}': Float mismatch: {exp_val} != {act_val}"
                        )
            elif isinstance(exp_val, int):
                if not isinstance(act_val, int) or isinstance(act_val, bool):
                    errors.append(
                        f"Row {row_idx}, key '{key}': Expected int, got {type(act_val).__name__} ({act_val!r})"
                    )
                elif exp_val != act_val:
                    errors.append(
                        f"Row {row_idx}, key '{key}': Int mismatch: {exp_val} != {act_val}"
                    )
            else:
                if exp_val != act_val:
                    errors.append(
                        f"Row {row_idx}, key '{key}': Value mismatch: {exp_val!r} != {act_val!r}"
                    )

    is_valid = len(errors) == 0
    return is_valid, errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert CSV dataset to typed JSON array-of-objects format."
    )
    parser.add_argument(
        "input_csv",
        type=str,
        nargs="?",
        help="Path to input CSV file.",
    )
    parser.add_argument(
        "output_json",
        type=str,
        nargs="?",
        help="Path to output JSON file.",
    )
    parser.add_argument(
        "-i",
        "--input",
        dest="opt_input",
        type=str,
        help="Path to input CSV file (alternative option).",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="opt_output",
        type=str,
        help="Path to output JSON file (alternative option).",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indentation level (default: 2).",
    )

    args = parser.parse_args()

    input_path = args.input_csv or args.opt_input
    output_path = args.output_json or args.opt_output

    if not input_path or not output_path:
        parser.error("Both input CSV and output JSON paths are required.")

    try:
        summary = convert_csv_to_json(input_path, output_path, indent=args.indent)
        is_valid, errors = validate_conversion(input_path, output_path)

        print(f"Input CSV:      {summary['input_csv']}")
        print(f"Output JSON:    {summary['output_json']}")
        print(f"CSV rows:       {summary['row_count']}")
        print(f"JSON objects:   {summary['row_count']}")
        print(f"Columns:        {summary['column_count']}")
        print(f"Keys match:     {'YES' if is_valid else 'NO'}")
        print(f"Values match:   {'YES' if is_valid else 'NO'}")
        print(f"JSON valid:     {'YES' if is_valid else 'NO'}")

        if not is_valid:
            print(f"Validation errors ({len(errors)}):")
            for err in errors[:10]:
                print(f"  - {err}")
            return 1
        return 0

    except Exception as e:
        print(f"Error during conversion: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
