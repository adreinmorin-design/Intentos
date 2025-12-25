"""Simple Speaker Registry with optional dependency on `resemblyzer`.

Behavior:
- If `resemblyzer` is available, use it to create speaker embeddings and match via cosine similarity.
- If not available, fallback to a deterministic SHA256 fingerprint of the audio bytes (exact-match only).
- Stores enrolled speakers in `config/speakers.json`.
- Designed for local-only, opt-in usage. Calls to these functions should be gated by user consent.
"""
from typing import Optional, Dict, Any
import os
import json
import hashlib
import math
from resemblyzer import VoiceEncoder, preprocess_wav

try:
    from resemblyzer import VoiceEncoder, preprocess_wav
    RESEMBLYZER_AVAILABLE = True
except ImportError:
    RESEMBLYZER_AVAILABLE = False

class SpeakerRegistry:
    def __init__(self, paths):
        self.paths = paths
        self.speakers_file = os.path.join(paths.config_dir, "speakers.json")
        self._load()
        self.available = RESEMBLYZER_AVAILABLE
        if self.available:
            try:
                self._encoder = VoiceEncoder()
            except Exception:
                self.available = False

    def _load(self):
        try:
            if not os.path.exists(self.speakers_file):
                self.speakers = {}
                return
            with open(self.speakers_file, "r", encoding="utf-8") as f:
                self.speakers = json.load(f)
        except Exception:
            self.speakers = {}

    def _persist(self):
        try:
            with open(self.speakers_file, "w", encoding="utf-8") as f:
                json.dump(self.speakers, f, indent=2)
        except Exception:
            pass

    def _fingerprint(self, audio_bytes: bytes) -> str:
        # Fallback deterministic fingerprint
        return hashlib.sha256(audio_bytes).hexdigest()

    def enroll(self, user_id: str, audio_bytes: bytes) -> bool:
        """Enroll a user using raw WAV bytes (or any audio bytes)."""
        try:
            if self.available:
                # Use resemblyzer to create embedding
                wav = preprocess_wav(audio_bytes)
                emb = list(self._encoder.embed_utterance(wav))
                self.speakers[user_id] = {"type": "embedding", "vector": emb}
                self._persist()
                return True
            else:
                # Fallback: store fingerprint
                fp = self._fingerprint(audio_bytes)
                self.speakers[user_id] = {"type": "fingerprint", "fp": fp}
                self._persist()
                return True
        except Exception:
            return False

    def identify(self, audio_bytes: bytes, threshold: float = 0.7) -> Optional[str]:
        """Attempt to identify speaker from audio bytes.
        Returns user_id if matched, otherwise None.
        """
        try:
            if self.available:
                wav = preprocess_wav(audio_bytes)
                emb = self._encoder.embed_utterance(wav)
                best = None
                best_sim = -1.0
                for uid, meta in self.speakers.items():
                    if meta.get("type") != "embedding":
                        continue
                    vec = meta.get("vector", [])
                    # cosine similarity
                    num = sum(a * b for a, b in zip(vec, emb))
                    den_a = math.sqrt(sum(a * a for a in vec))
                    den_b = math.sqrt(sum(b * b for b in emb))
                    if den_a == 0 or den_b == 0:
                        continue
                    sim = num / (den_a * den_b)
                    if sim > best_sim:
                        best_sim = sim
                        best = uid
                if best and best_sim >= threshold:
                    return best
                return None
            else:
                fp = self._fingerprint(audio_bytes)
                for uid, meta in self.speakers.items():
                    if meta.get("type") == "fingerprint" and meta.get("fp") == fp:
                        return uid
                return None
        except Exception:
            return None

    def list_speakers(self) -> Dict[str, Any]:
        return dict(self.speakers)

    def remove(self, user_id: str) -> bool:
        if user_id in self.speakers:
            del self.speakers[user_id]
            self._persist()
            return True
        return False
