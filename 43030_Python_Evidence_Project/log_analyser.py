"""Introductory authentication-log analysis exercise using fictional CSV data.

Flags IP addresses with at least `threshold` failed logins.
A flag indicates a need for review; it does not establish malicious activity.
"""
import argparse
import csv
from collections import Counter
from pathlib import Path


def analyse(path: Path, threshold: int = 3) -> tuple[Counter, list[tuple[str, int]]]:
    if threshold < 1:
        raise ValueError("Threshold must be positive")
    failures = Counter()
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        required = {"timestamp", "username", "ip_address", "status"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("CSV missing required columns")
        for row in reader:
            if row["status"].strip().lower() == "failed":
                failures[row["ip_address"].strip()] += 1
    flagged = sorted(((ip, count) for ip, count in failures.items()
                      if count >= threshold), key=lambda item: (-item[1], item[0]))
    return failures, flagged


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_file", type=Path)
    parser.add_argument("--threshold", type=int, default=3)
    args = parser.parse_args()
    failures, flagged = analyse(args.csv_file, args.threshold)
    print("FAILED LOGIN ATTEMPTS BY IP")
    for ip, count in sorted(failures.items()):
        print(f"  {ip}: {count}")
    print(f"\nREQUIRES REVIEW ({args.threshold}+ failed attempts)")
    if not flagged:
        print("  None")
    for ip, count in flagged:
        print(f"  {ip}: {count} failed attempts")
    print("\nNote: Flagged activity is not proof of an attack.")


if __name__ == "__main__":
    main()
