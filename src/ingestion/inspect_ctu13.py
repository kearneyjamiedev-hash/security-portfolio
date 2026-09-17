import csv
from pathlib import Path

file_path = Path(input("Path to CTU-13 file: ").strip().strip('"'))

with file_path.open("r", encoding="utf-8", newline="") as file:
    reader = csv.DictReader(file)
    first_record = next(reader)

print(first_record)