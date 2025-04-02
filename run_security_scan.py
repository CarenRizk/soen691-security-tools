import os
import subprocess
import json
import xml.etree.ElementTree as ET
import csv

FILES_DIR = "python_vuln_files"
RESULTS_DIR = "results"
os.makedirs(RESULTS_DIR, exist_ok=True)

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

def main():
    # Prepare CSV files
      with open("semgrep_results.csv", "w", newline="", encoding="utf-8") as semgrep_csv, \
             open("bandit_results.csv", "w", newline="", encoding="utf-8") as bandit_csv:

        semgrep_writer = csv.writer(semgrep_csv)
        bandit_writer = csv.writer(bandit_csv)

        for writer in [semgrep_writer, bandit_writer]:
            writer.writerow(["filename", "line", "severity", "message", "cwe"])

        for filename in os.listdir(FILES_DIR):
            if not filename.endswith(".py"):
                continue

            file_path = os.path.join(FILES_DIR, filename)
            print(f"\n🔍 Scanning: {filename}")

            run_semgrep(file_path, filename, semgrep_writer)
            run_bandit(file_path, filename, bandit_writer)
        print("\n✅ Results saved to: semgrep_results.csv, bandit_results.csv")

if __name__ == "__main__":
    main()
