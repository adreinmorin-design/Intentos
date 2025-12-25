#!/usr/bin/env sh
set -e
python -m pip install --upgrade pip
python -m pip install -r requirements-optional.txt

echo "Optional dependencies installed. For Vosk models see docs/DEPENDENCIES.md"
