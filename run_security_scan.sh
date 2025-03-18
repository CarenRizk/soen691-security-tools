#!/bin/bash

# Activate virtual environment
source venv/bin/activate

# Define the Python file to scan
FILE="brute.py"

# Ensure file exists
if [ ! -f "$FILE" ]; then
  echo "File not found: $FILE"
  exit 1
fi

echo "Running Semgrep..."
semgrep --config "p/python" --json --output semgrep_results.json "$FILE"

echo "Running RATS..."
rats -w 3 --xml -d -r "$FILE" > rats_results.xml

echo "Running Bandit..."
bandit -r "$FILE" -o bandit_results.json -f json

echo "Parsing Results..."
python3 parse_results.py

echo "Security Scan Completed. Check security_vulnerabilities.csv."

# Deactivate virtual environment
deactivate
