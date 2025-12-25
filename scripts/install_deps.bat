@echo off
REM Install optional dependencies for full microphone and keyword spotting functionality
python -m pip install --upgrade pip
python -m pip install -r requirements-optional.txt

echo Optional dependencies installed. For Vosk models see docs/DEPENDENCIES.md
pause