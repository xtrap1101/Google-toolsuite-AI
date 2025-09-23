#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Define project directory and navigate into it
PROJECT_DIR="/home/tongtongtong/Google-toolsuite-AI"
cd $PROJECT_DIR

# Pull the latest code from the main branch
echo ">>> Pulling latest code from GitHub..."
git pull origin main

# Activate virtualenv and install dependencies
echo ">>> Installing dependencies..."
source venv/bin/activate
pip install -r requirements.txt

echo ">>> Update script finished."