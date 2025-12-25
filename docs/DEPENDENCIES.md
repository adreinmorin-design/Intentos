# Optional Dependencies and Models

This project has optional dependencies for enhanced microphone capture, keyword spotting, and desktop notifications.

## Optional Python packages
Install the optional packages with:

    python -m pip install -r requirements-optional.txt

- sounddevice: real-time audio capture
- numpy: numerical operations used by audio processing
- vosk: offline speech recognition used for keyword spotting
- win10toast: Windows desktop notifications helper

## Vosk model
To enable keyword spotting using Vosk, download a small model (e.g., `vosk-model-small-en-us-0.15`) and place it in either:

- `misc/vosk-model-small/`
- `plugins/vosk-model-small/`

Example download and extraction (Linux/macOS):

    mkdir -p misc
    wget https://alphacephei.com/vosk/models/vosk-model-small-en-us-0.15.zip
    unzip vosk-model-small-en-us-0.15.zip -d misc/
    mv misc/vosk-model-small-en-us-0.15 misc/vosk-model-small

Once a model is present, restart the GUI. The KeywordSpotter will attempt to load the model automatically.

## Troubleshooting
- If audio capture fails on Windows, ensure the app has microphone permission in Settings -> Privacy -> Microphone.
- On macOS, check System Preferences -> Security & Privacy -> Privacy -> Microphone.
- On Linux (GNOME), check Settings -> Privacy -> Microphone.

