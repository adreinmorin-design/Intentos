from pathlib import Path
from typing import Optional
from voice_profile import extract_voice_embedding, train_mimic_model, VoiceProfile

class VoiceManager:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.profiles: dict[str, VoiceProfile] = {}
        self.active_profile: Optional[str] = None

    def upload_voice(self, user_id: str, audio_path: Path) -> str:
        emb = extract_voice_embedding(audio_path)
        model_path = train_mimic_model(audio_path, self.base_dir / user_id)
        profile = VoiceProfile(user_id=user_id, embedding=emb, model_path=model_path)
        self.profiles[user_id] = profile
        self.active_profile = user_id
        return f"Voice profile for {user_id} activated."

    def switch_voice(self, user_id: str) -> str:
        if user_id not in self.profiles:
            return f"No voice profile found for {user_id}."
        self.active_profile = user_id
        return f"Switched to voice profile: {user_id}"

    def get_active_voice(self) -> Optional[VoiceProfile]:
        if self.active_profile:
            return self.profiles.get(self.active_profile)
        return None