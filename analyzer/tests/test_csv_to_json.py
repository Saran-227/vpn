import csv
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.csv_to_json import (
    convert_csv_to_json,
    parse_value,
    read_csv_to_records,
    validate_conversion,
)


class TestCsvToJson(unittest.TestCase):
    def setUp(self):
        self.sample_csv_data = (
            "flow_id,src_ip,dst_ip,src_port,dst_port,protocol,packet_count,total_bytes,flow_duration_seconds\n"
            "flow_1,100.119.32.83,100.127.207.119,500,500,UDP,2,592,0.0556278229\n"
            "flow_2,100.119.32.83,100.127.207.119,,,ESP,10,1400,1.25\n"
            "flow_3,10.0.0.1,10.0.0.2,4500,4500,UDP,555,461135,142.0182800293\n"
        )

    # 1. Normal CSV conversion
    def test_normal_csv_conversion(self):
        with TemporaryDirectory() as tmp_dir:
            csv_path = Path(tmp_dir) / "test.csv"
            json_path = Path(tmp_dir) / "test.json"

            csv_path.write_text(self.sample_csv_data, encoding="utf-8")
            summary = convert_csv_to_json(csv_path, json_path)

            self.assertTrue(json_path.exists())
            self.assertEqual(summary["row_count"], 3)
            self.assertEqual(summary["column_count"], 9)

            with json_path.open("r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertIsInstance(data, list)
            self.assertEqual(len(data), 3)

    # 2. Integer values
    def test_integer_values(self):
        self.assertEqual(parse_value("500"), 500)
        self.assertIsInstance(parse_value("500"), int)
        self.assertEqual(parse_value("0"), 0)
        self.assertIsInstance(parse_value("0"), int)
        self.assertEqual(parse_value("-42"), -42)
        self.assertIsInstance(parse_value("-42"), int)
        self.assertEqual(parse_value("+100"), 100)
        self.assertIsInstance(parse_value("+100"), int)

    # 3. Floating-point values
    def test_floating_point_values(self):
        self.assertEqual(parse_value("0.0556278229"), 0.0556278229)
        self.assertIsInstance(parse_value("0.0556278229"), float)
        self.assertEqual(parse_value("142.0"), 142.0)
        self.assertIsInstance(parse_value("142.0"), float)
        self.assertEqual(parse_value("5.0067901611328125e-06"), 5.0067901611328125e-06)
        self.assertIsInstance(parse_value("5.0067901611328125e-06"), float)

    # 4. String values
    def test_string_values(self):
        self.assertEqual(parse_value("flow_1"), "flow_1")
        self.assertEqual(parse_value("100.119.32.83"), "100.119.32.83")
        self.assertEqual(parse_value("UDP"), "UDP")
        self.assertEqual(parse_value("AES_GCM_16_256"), "AES_GCM_16_256")
        self.assertEqual(parse_value("PASS"), "PASS")
        # Special keywords that should not convert to float NaN/Inf
        self.assertEqual(parse_value("NaN"), "NaN")
        self.assertEqual(parse_value("nan"), "nan")
        self.assertEqual(parse_value("inf"), "inf")

    # 5. Empty/null values
    def test_empty_null_values(self):
        self.assertIsNone(parse_value(""))
        self.assertIsNone(parse_value(None))
        self.assertIsNone(parse_value("   "))

        with TemporaryDirectory() as tmp_dir:
            csv_path = Path(tmp_dir) / "null_test.csv"
            json_path = Path(tmp_dir) / "null_test.json"

            csv_path.write_text(
                "flow_id,src_port,dst_port,protocol\n"
                "flow_1,,,ESP\n",
                encoding="utf-8",
            )
            convert_csv_to_json(csv_path, json_path)

            with json_path.open("r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertIsNone(data[0]["src_port"])
            self.assertIsNone(data[0]["dst_port"])
            self.assertEqual(data[0]["protocol"], "ESP")

    # 6. Row-count preservation
    def test_row_count_preservation(self):
        with TemporaryDirectory() as tmp_dir:
            csv_path = Path(tmp_dir) / "rows.csv"
            json_path = Path(tmp_dir) / "rows.json"

            rows = ["id,val"] + [f"row_{i},{i * 10}" for i in range(100)]
            csv_path.write_text("\n".join(rows), encoding="utf-8")

            summary = convert_csv_to_json(csv_path, json_path)
            self.assertEqual(summary["row_count"], 100)

            with json_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(len(data), 100)

    # 7. Column preservation
    def test_column_preservation(self):
        columns = ["col_a", "col_b", "col_c", "col_d", "col_e"]
        with TemporaryDirectory() as tmp_dir:
            csv_path = Path(tmp_dir) / "cols.csv"
            json_path = Path(tmp_dir) / "cols.json"

            csv_path.write_text(",".join(columns) + "\n1,2,3,4,5\n", encoding="utf-8")
            summary = convert_csv_to_json(csv_path, json_path)

            self.assertEqual(summary["columns"], columns)

            with json_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(list(data[0].keys()), columns)

    # 8. JSON validity
    def test_json_validity(self):
        with TemporaryDirectory() as tmp_dir:
            csv_path = Path(tmp_dir) / "valid.csv"
            json_path = Path(tmp_dir) / "valid.json"

            csv_path.write_text(self.sample_csv_data, encoding="utf-8")
            convert_csv_to_json(csv_path, json_path)

            is_valid, errors = validate_conversion(csv_path, json_path)
            self.assertTrue(is_valid)
            self.assertEqual(errors, [])

    # 9. Empty CSV handling
    def test_empty_csv_handling(self):
        with TemporaryDirectory() as tmp_dir:
            # Case A: completely empty file (0 bytes)
            csv_empty = Path(tmp_dir) / "empty.csv"
            json_empty = Path(tmp_dir) / "empty.json"
            csv_empty.write_text("", encoding="utf-8")

            summary = convert_csv_to_json(csv_empty, json_empty)
            self.assertEqual(summary["row_count"], 0)
            self.assertEqual(summary["column_count"], 0)

            with json_empty.open("r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data, [])

            # Case B: Header-only CSV
            csv_header_only = Path(tmp_dir) / "header_only.csv"
            json_header_only = Path(tmp_dir) / "header_only.json"
            csv_header_only.write_text("col1,col2,col3\n", encoding="utf-8")

            summary_h = convert_csv_to_json(csv_header_only, json_header_only)
            self.assertEqual(summary_h["row_count"], 0)
            self.assertEqual(summary_h["column_count"], 3)

            with json_header_only.open("r", encoding="utf-8") as f:
                data_h = json.load(f)
            self.assertEqual(data_h, [])

    # 10. Missing input file handling
    def test_missing_input_file_handling(self):
        with TemporaryDirectory() as tmp_dir:
            non_existent_csv = Path(tmp_dir) / "does_not_exist.csv"
            output_json = Path(tmp_dir) / "out.json"

            with self.assertRaises(FileNotFoundError):
                convert_csv_to_json(non_existent_csv, output_json)


if __name__ == "__main__":
    unittest.main()
