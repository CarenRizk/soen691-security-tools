import json
import xml.etree.ElementTree as ET
import pandas as pd
import os

# Load Semgrep results
semgrep_findings = []
if os.path.exists("semgrep_results.json") and os.path.getsize("semgrep_results.json") > 0:
    try:
        with open("semgrep_results.json") as f:
            semgrep_data = json.load(f)

        semgrep_findings = [
            {
                "tool": "Semgrep",
                "file": result["path"],
                "line": result["start"]["line"],
                "severity": result["extra"].get("severity", "Unknown"),
                "message": result["extra"]["message"],
                "rule_id": result["check_id"]
            }
            for result in semgrep_data.get("results", [])
        ]
    except (FileNotFoundError, json.JSONDecodeError):
        print("Error: Semgrep JSON output is invalid or empty. Skipping Semgrep results.")
else:
    print("Warning: Semgrep output is empty or missing. Skipping Semgrep results.")

# Load RATS results
rats_findings = []
if os.path.exists("rats_results.xml") and os.path.getsize("rats_results.xml") > 0:
    try:
        tree = ET.parse("rats_results.xml")
        root = tree.getroot()

        rats_findings = [
            {
                "tool": "RATS",
                "file": vuln.find("file").text,
                "line": vuln.find("line").text if vuln.find("line") is not None else "N/A",
                "severity": vuln.find("severity").text if vuln.find("severity") is not None else "Unknown",
                "message": vuln.find("description").text if vuln.find("description") is not None else "No description",
                "rule_id": vuln.find("type").text if vuln.find("type") is not None else "N/A"
            }
            for vuln in root.findall("vulnerability")
        ]
    except ET.ParseError:
        print("Error: RATS XML output is invalid or empty. Skipping RATS parsing.")
else:
    print("Warning: RATS output is empty or missing. Skipping RATS results.")

# Load Bandit results
bandit_findings = []
if os.path.exists("bandit_results.json") and os.path.getsize("bandit_results.json") > 0:
    try:
        with open("bandit_results.json") as f:
            bandit_data = json.load(f)

        bandit_findings = [
            {
                "tool": "Bandit",
                "file": issue["filename"],
                "line": issue["line_number"],
                "severity": issue["issue_severity"],
                "message": issue["issue_text"],
                "rule_id": issue["test_id"]
            }
            for issue in bandit_data["results"]
        ]
    except (FileNotFoundError, json.JSONDecodeError):
        print("Error: Bandit JSON output is invalid or empty. Skipping Bandit results.")
else:
    print("Warning: Bandit output is empty or missing. Skipping Bandit results.")

# Save each tool's results in separate CSV files
if semgrep_findings:
    pd.DataFrame(semgrep_findings).to_csv("semgrep_results.csv", index=False)
    print("✅ Semgrep results saved to semgrep_results.csv")

if rats_findings:
    pd.DataFrame(rats_findings).to_csv("rats_results.csv", index=False)
    print("✅ RATS results saved to rats_results.csv")

if bandit_findings:
    pd.DataFrame(bandit_findings).to_csv("bandit_results.csv", index=False)
    print("✅ Bandit results saved to bandit_results.csv")

print("✅ Analysis completed. Individual results saved for each tool.")
