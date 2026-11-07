"""Tests for the sample learning exercise. Run: python -m unittest -v"""
import csv
import tempfile
import unittest
from pathlib import Path
from log_analyser import analyse


class TestLogAnalyser(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.csv_path = Path(self.temp.name) / "sample.csv"
        with self.csv_path.open("w", newline="", encoding="utf-8") as out:
            writer = csv.writer(out)
            writer.writerow(["timestamp", "username", "ip_address", "status"])
            for i, status in enumerate(["failed", "failed", "failed", "success"]):
                writer.writerow([f"2026-11-05T09:0{i}:00", "alice", "192.0.2.10", status])

    def tearDown(self):
        self.temp.cleanup()

    def test_three_failures_flagged(self):
        counts, flagged = analyse(self.csv_path)
        self.assertEqual(counts["192.0.2.10"], 3)
        self.assertEqual(flagged, [("192.0.2.10", 3)])

    def test_higher_threshold_no_flags(self):
        _, flagged = analyse(self.csv_path, threshold=4)
        self.assertEqual(flagged, [])

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            analyse(self.csv_path, threshold=0)

    def test_missing_columns(self):
        self.csv_path.write_text("username,status\nalice,failed\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            analyse(self.csv_path)


if __name__ == "__main__":
    unittest.main()
