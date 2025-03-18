#!/bin/bash

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Semgrep inside venv
pip install semgrep

# Install RATS using Homebrew (outside venv)
brew install rats

pip install bandit

echo "Installation complete! Run 'source venv/bin/activate' to activate the virtual environment."
