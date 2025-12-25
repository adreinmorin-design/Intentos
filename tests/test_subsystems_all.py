import os
import tempfile
from intentos_wizard_automation import (
    WizardConfig,
    WizardContext,
    BackendSubsystem,
    DashboardSubsystem,
    CLISubsystem,
    VSCodeExtensionSubsystem,
    ElectronSubsystem,
    LegalSubsystem,
    ConfigSubsystem,
    MiscSubsystem,
    TestsSubsystem,
)


def test_all_subsystems_scaffold_files_created():
    with tempfile.TemporaryDirectory() as td:
        cfg = WizardConfig(repo_root=td)
        ctx = WizardContext(config=cfg)

        subs = [
            BackendSubsystem(ctx, engine_path="/nonexistent/root"),
            DashboardSubsystem(ctx),
            CLISubsystem(ctx, engine_path="/nonexistent/root"),
            VSCodeExtensionSubsystem(ctx),
            ElectronSubsystem(ctx),
            LegalSubsystem(ctx),
            ConfigSubsystem(ctx),
            MiscSubsystem(ctx),
            TestsSubsystem(ctx),
        ]

        for s in subs:
            s.scaffold()

        # Verify expected files exist
        assert os.path.exists(os.path.join(td, "backend", "main.py"))
        assert os.path.exists(os.path.join(td, "dashboard", "index.html"))
        assert os.path.exists(os.path.join(td, "cli", "cli.py"))
        assert os.path.exists(os.path.join(td, "vscode_extension", "package.json"))
        assert os.path.exists(os.path.join(td, "electron_app", "package.json"))
        assert os.path.exists(os.path.join(td, "electron_app", "main.js"))
        assert os.path.exists(os.path.join(td, "legal", "LICENSE.txt"))
        assert os.path.exists(os.path.join(td, "legal", "PRIVACY_POLICY.txt"))
        assert os.path.exists(os.path.join(td, "config", "intentos_config.json"))
        assert os.path.exists(os.path.join(td, "misc", "README_MISC.md"))
        assert os.path.exists(os.path.join(td, "tests", "test_smoke.py"))
