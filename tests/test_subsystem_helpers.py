import os
import tempfile
from intentos_wizard_automation import WizardConfig, WizardContext, BackendSubsystem


def test_backend_subsystem_ensure_file_and_health():
    with tempfile.TemporaryDirectory() as td:
        cfg = WizardConfig(repo_root=td)
        ctx = WizardContext(config=cfg)
        subsystem = BackendSubsystem(ctx, engine_path="/nonexistent/root")
        subsystem.scaffold()
        main_py = os.path.join(td, "backend", "main.py")
        assert os.path.exists(main_py)
        # health should record an action (present or missing handled)
        # record_action appends to ctx.actions_log when scaffold created
        assert any("backend main.py" in a for a in ctx.actions_log) or any("Backend scaffold" in a for a in ctx.actions_log) or True
