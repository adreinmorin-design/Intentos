class VoiceEngine:
    def __init__(self, voice_manager: VoiceManager):
        self.voice_manager = voice_manager

    def respond(self, raw_text: str) -> dict:
        shaped = self.shape_text(raw_text)
        audio = self.synthesize(shaped)
        return {
            "text": shaped,
            "audio_bytes": audio,
            "voice_id": self.voice_manager.active_profile,
        }

    def shape_text(self, text: str) -> str:
        return text.strip().capitalize()

    def synthesize(self, text: str) -> bytes:
        profile = self.voice_manager.get_active_voice()
        if profile:
            # TODO: use mimic model at profile.model_path
            return b"FAKE_AUDIO_BYTES"  # Replace with actual synthesis
        return b""