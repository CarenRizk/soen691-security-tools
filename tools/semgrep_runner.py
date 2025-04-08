# tools/semgrep_runner.py
import os
import subprocess
import json
import csv
from config import RESULTS_DIR

def run_semgrep(file_path, filename, writer):
    base_name = os.path.splitext(filename)[0]
    output_path = f"{RESULTS_DIR}/{base_name}_semgrep.json"

    subprocess.run([
        "semgrep", "--config", "p/python",
        "--json", "--output", output_path, file_path
    ], check=True)

    with open(output_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        for result in data.get("results", []):
            message = result.get("extra", {}).get("message", "")
            severity = result.get("extra", {}).get("severity", "")
            line = result.get("start", {}).get("line", "")
            cwe = result.get("extra", {}).get("metadata", {}).get("cwe", "")
            writer.writerow([filename, line, severity, message, cwe])
