import tempfile
from gui_intentos.context_memory import ContextMemory
from gui_intentos.gui_intentos import IntentOSPaths


def test_memory_add_and_get():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        cm = ContextMemory(paths)
        cm.add_memory("alice", "note", "Alice likes tea")
        cm.add_memory("alice", "note", "Alice prefers Python")
        mem = cm.get_memory("alice")
        assert len(mem) == 2
        assert mem[-1]["text"] == "Alice prefers Python"


def test_clear_memory():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        cm = ContextMemory(paths)
        cm.add_memory("bob", "fact", "Bob is admin")
        cm.clear_memory("bob")
        assert cm.get_memory("bob") == []
        cm.add_memory("x", "a", "1")
        cm.clear_memory()
        assert cm.get_memory("x") == []
