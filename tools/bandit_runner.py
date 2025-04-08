# tools/bandit_runner.py
import os
import subprocess
import json
import csv
from config import RESULTS_DIR

def run_bandit(file_path, filename, writer):
    base_name = os.path.splitext(filename)[0]
    output_path = f"{RESULTS_DIR}/{base_name}_bandit.json"

    result = subprocess.run([
        "bandit", "-r", file_path,
        "-o", output_path, "-f", "json"
    ], capture_output=True, text=True)

    if result.returncode not in [0, 1]:  # 0 = clean, 1 = issues found
        print(f"❌ Bandit error for {filename}: {result.stderr.strip()}")
        return

    try:
        with open(output_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            results = data.get("results", [])
            if not results:
                print(f"ℹ️  No Bandit issues in {filename}")
            for result in results:
                message = result.get("issue_text", "")
                severity = result.get("issue_severity", "")
                line = result.get("line_number", "")
                cwe = result.get("issue_cwe", {}).get("id", "") if result.get("issue_cwe") else ""
                writer.writerow([filename, line, severity, message, cwe])
    except Exception as e:
        print(f"⚠️ Failed to parse Bandit output for {filename}: {e}")
