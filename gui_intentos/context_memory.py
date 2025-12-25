"""Simple context memory storage per user.

Stores short memory entries (ts, type, text) per user in `config/memory.json`.
Designed to be local-only and respect privacy; read/write helpers are provided.
"""
from typing import List, Dict, Any, Optional
import os
import json
from datetime import datetime


class ContextMemory:
    def __init__(self, paths):
        self.paths = paths
        self.memory_file = os.path.join(paths.config_dir, "memory.json")
        self._load()

    def _load(self):
        try:
            if not os.path.exists(self.memory_file):
                self.mem = {}
                return
            with open(self.memory_file, "r", encoding="utf-8") as f:
                self.mem = json.load(f)
        except Exception:
            self.mem = {}

    def _persist(self):
        try:
            with open(self.memory_file, "w", encoding="utf-8") as f:
                json.dump(self.mem, f, indent=2)
        except Exception:
            pass

    def add_memory(self, user_id: str, kind: str, text: str) -> None:
        entry = {"ts": datetime.utcnow().isoformat() + "Z", "kind": kind, "text": text}
        lst = self.mem.setdefault(user_id, [])
        lst.append(entry)
        # Keep only last 200 entries to bound size
        if len(lst) > 200:
            lst[:] = lst[-200:]
        self._persist()

    def get_memory(self, user_id: str, limit: Optional[int] = 50) -> List[Dict[str, Any]]:
        return list(self.mem.get(user_id, [])[-(limit or 50):])

    def clear_memory(self, user_id: Optional[str] = None) -> None:
        if user_id is None:
            self.mem = {}
        else:
            self.mem.pop(user_id, None)
        self._persist()
