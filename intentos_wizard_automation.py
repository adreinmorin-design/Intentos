#!/usr/bin/env python
"""
IntentOS Engine Builder (single-file modular engine)

This script is the self-contained automation brain for IntentOS.

It assumes the canonical engine is the "root" file on GitHub and
that locally you may have *nothing* except the cloned repo directory.

On every run, it:

1. Fetches the latest "root" from GitHub raw URL.
2. Overwrites the local ./root file (source of truth).
3. Scaffolds all subsystems around it:
   - backend/          (FastAPI wrapper)
   - dashboard/        (static HTML)
   - cli/              (wrapper that can run root)
   - vscode_extension/ (VS Code extension stub)
   - electron_app/     (desktop shell stub)
   - legal/            (license/policy placeholders)
   - config/           (base config JSON)
   - misc/             (scratch/notes)
   - tests/            (smoke test)
4. Runs a CLI smoke test.
5. Launches backend (non-blocking).
6. Opens dashboard in the default browser.
7. Optionally launches Electron (configurable).

Everything is contained in this single file and internally modularized
via classes and subsystem abstractions.

The only hard overwrite is ./root; everything else is created only if missing.
"""

import os
import sys
import subprocess
import textwrap
import webbrowser
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict
from urllib.request import urlopen


# ===========================================================================
# Core configuration and context
# ===========================================================================

@dataclass
class WizardConfig:
    """Configuration for the engine builder."""
    repo_root: str
    root_github_raw_url: str = (
        "https://raw.githubusercontent.com/adreinmorin-design/Intentos/main/root"
    )
    root_engine_filename: str = "root"
    default_branch: str = "main"
    enable_git: bool = True
    auto_launch_backend: bool = True
    auto_open_dashboard: bool = True
    auto_launch_electron: bool = False  # opt-in when ready


@dataclass
class WizardContext:
    """Runtime context and logs for this run."""
    config: WizardConfig
    actions_log: List[str] = field(default_factory=list)
    errors_log: List[str] = field(default_factory=list)


# ===========================================================================
# Logging and command helpers
# ===========================================================================

def banner(title: str) -> None:
    line = "=" * max(40, len(title) + 8)
    print()
    print(line)
    print(f"  {title}")
    print(line)
    print()


def section(title: str) -> None:
    print()
    print(f"--- {title} ---")
    print()


def info(msg: str) -> None:
    print(f"[INFO] {msg}")


def warn(msg: str) -> None:
    print(f"[WARN] {msg}")


def error(msg: str) -> None:
    print(f"[ERROR] {msg}", file=sys.stderr)


def record_action(ctx: WizardContext, msg: str) -> None:
    ctx.actions_log.append(msg)
    info(msg)


def record_error(ctx: WizardContext, msg: str) -> None:
    ctx.errors_log.append(msg)
    error(msg)


def run_cmd(
    ctx: WizardContext,
    cmd: List[str],
    cwd: Optional[str] = None,
    allow_fail: bool = False,
    label: Optional[str] = None,
    background: bool = False,
) -> Optional[subprocess.Popen]:
    """
    Run a subprocess with structured logging.

    - background=False: run and wait, log stdout/stderr.
    - background=True: start and return Popen without waiting.
    """
    label = label or " ".join(cmd)
    info(f"Running command: {label}")
    try:
        if background:
            proc = subprocess.Popen(
                cmd,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            record_action(ctx, f"Started background process: {label} (pid={proc.pid})")
            return proc
        else:
            result = subprocess.run(
                cmd,
                cwd=cwd,
                check=not allow_fail,
                capture_output=True,
                text=True,
            )
            if result.stdout:
                print(result.stdout.strip())
            if result.stderr:
                warn(result.stderr.strip())
            return None
    except subprocess.CalledProcessError as e:
        record_error(ctx, f"Command failed ({label}): {e}")
        if e.stdout:
            print(e.stdout.strip())
        if e.stderr:
            error(e.stderr.strip())
        if not allow_fail:
            raise
    except FileNotFoundError as e:
        record_error(ctx, f"Command not found ({label}): {e}")
        if not allow_fail:
            raise
    return None


# ===========================================================================
# Filesystem helpers
# ===========================================================================

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_if_missing(ctx: WizardContext, path: str, content: str, description: str) -> None:
    if os.path.exists(path):
        info(f"{description} already exists at {path}; skipping.")
        return
    ensure_dir(os.path.dirname(path))
    record_action(ctx, f"Creating {description} at {path}")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


# ===========================================================================
# Root engine management (source-of-truth: GitHub)
# ===========================================================================

class RootEngineManager:
    """Responsible for syncing the root engine file from GitHub."""

    def __init__(self, ctx: WizardContext) -> None:
        self.ctx = ctx

    def sync_from_github(self) -> str:
        banner("Syncing root engine from GitHub")

        url = self.ctx.config.root_github_raw_url
        local_root_path = os.path.join(
            self.ctx.config.repo_root,
            self.ctx.config.root_engine_filename,
        )

        info(f"Fetching canonical root from: {url}")
        try:
            with urlopen(url) as resp:
                if resp.status != 200:
                    msg = f"Failed to fetch root from GitHub (HTTP {resp.status})."
                    record_error(self.ctx, msg)
                    raise SystemExit(1)
                content = resp.read()
        except Exception as e:
            record_error(self.ctx, f"Error fetching root from GitHub: {e}")
            raise SystemExit(1)

        # Overwrite local root
        try:
            with open(local_root_path, "wb") as f:
                f.write(content)
            record_action(
                self.ctx,
                f"Overwrote local root with latest GitHub version at {local_root_path}",
            )
        except Exception as e:
            record_error(self.ctx, f"Failed to write local root file: {e}")
            raise SystemExit(1)

        # Mark executable on Unix-like systems (no-op on Windows)
        try:
            mode = os.stat(local_root_path).st_mode
            os.chmod(local_root_path, mode | 0o111)
        except Exception:
            pass

        return local_root_path


# ===========================================================================
# Subsystem base and implementations
# ===========================================================================

class Subsystem:
    """Base class for all subsystems."""

    name: str = "base"
    description: str = "Base subsystem"

    def __init__(self, ctx: WizardContext) -> None:
        self.ctx = ctx

    @property
    def root_dir(self) -> str:
        return self.ctx.config.repo_root

    def ensure_file(self, relpath: str, content: str, description: str) -> None:
        """Ensure a file exists under the subsystem dir; idempotent."""
        path = os.path.join(self.root_dir, self.name, relpath)
        ensure_dir(os.path.dirname(path))
        write_if_missing(self.ctx, path, content, description)

    def check_file(self, relpath: str, present_message: str, missing_message: str) -> None:
        path = os.path.join(self.root_dir, self.name, relpath)
        if os.path.exists(path):
            record_action(self.ctx, present_message)
        else:
            warn(missing_message)

    def scaffold(self) -> None:
        """Create minimal structure/files (idempotent)."""
        raise NotImplementedError

    def health(self) -> None:
        """Optional health summary hook."""
        pass

    def smoke(self) -> None:
        """Optional smoke test hook."""
        pass

    def launch(self) -> None:
        """Optional launch hook."""
        pass


class BackendSubsystem(Subsystem):
    name = "backend"
    description = "FastAPI backend wrapper around root"

    def __init__(self, ctx: WizardContext, engine_path: str) -> None:
        super().__init__(ctx)
        self.engine_path = engine_path

    @property
    def path(self) -> str:
        return os.path.join(self.root_dir, "backend")

    def scaffold(self) -> None:
        section("Subsystem: backend")

        content = textwrap.dedent(
            f"""
            \"\"\"IntentOS backend wrapper (scaffold).

            Minimal FastAPI service that can later delegate
            to the main 'root' engine at:

                {self.engine_path}
            \"\"\"
            from fastapi import FastAPI
            import uvicorn
            import os

            app = FastAPI(title="IntentOS Backend (scaffold)")

            ROOT_ENGINE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "root"))

            @app.get("/health")
            async def health():
                return {{
                    "status": "ok",
                    "service": "backend",
                    "root_exists": os.path.exists(ROOT_ENGINE),
                }}

            if __name__ == "__main__":
                uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
            """
        ).strip() + "\n"

        # Use shared helper to create file
        self.ensure_file("main.py", content, "backend main.py")

    def health(self) -> None:
        self.check_file("main.py", "Backend scaffold present (backend/main.py).", "Backend scaffold missing (backend/main.py).")

    def launch(self) -> None:
        if not self.ctx.config.auto_launch_backend:
            info("Auto-launch backend disabled by config; skipping.")
            return

        section("Launching backend (background)")

        backend_main = os.path.join(self.path, "main.py")
        if not os.path.exists(backend_main):
            warn("Backend main.py not found; cannot launch backend.")
            return

        run_cmd(
            self.ctx,
            [sys.executable, "main.py"],
            cwd=self.path,
            allow_fail=True,
            label="backend main.py",
            background=True,
        )


class DashboardSubsystem(Subsystem):
    name = "dashboard"
    description = "Minimal static dashboard UI"

    @property
    def path(self) -> str:
        return os.path.join(self.root_dir, "dashboard")

    def scaffold(self) -> None:
        section("Subsystem: dashboard")

        content = textwrap.dedent(
            """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>IntentOS Dashboard</title>
                <style>
                    body { font-family: system-ui, sans-serif; margin: 2rem; background: #050816; color: #e5e7eb; }
                    .card { background: #111827; padding: 1.5rem; border-radius: 0.75rem; margin-bottom: 1rem; }
                    h1 { margin-top: 0; }
                    code { background: #1f2937; padding: 0.2rem 0.4rem; border-radius: 0.25rem; }
                </style>
            </head>
            <body>
                <h1>IntentOS Dashboard (Scaffold)</h1>
                <div class="card">
                    <p>This is a minimal, static dashboard scaffold.</p>
                    <p>
                        The automation wizard can open this automatically
                        after scaffolding (on supported systems).
                    </p>
                </div>
            </body>
            </html>
            """
        ).strip() + "\n"

        # Use Subsystem helper
        self.ensure_file("index.html", content, "dashboard index.html")

    def health(self) -> None:
        self.check_file("index.html", "Dashboard scaffold present (dashboard/index.html).", "Dashboard scaffold missing (dashboard/index.html).")

    def launch(self) -> None:
        if not self.ctx.config.auto_open_dashboard:
            info("Auto-open dashboard disabled by config; skipping.")
            return

        section("Opening dashboard in browser")

        index_html = os.path.join(self.path, "index.html")
        if not os.path.exists(index_html):
            warn("Dashboard index.html not found; cannot open dashboard.")
            return

        url = f"file:///{index_html.replace(os.sep, '/')}"
        record_action(self.ctx, f"Opening dashboard: {url}")
        try:
            webbrowser.open(url)
        except Exception as e:
            record_error(self.ctx, f"Failed to open dashboard in browser: {e}")


class CLISubsystem(Subsystem):
    name = "cli"
    description = "CLI wrapper that can delegate to root"

    def __init__(self, ctx: WizardContext, engine_path: str) -> None:
        super().__init__(ctx)
        self.engine_path = engine_path

    @property
    def path(self) -> str:
        return os.path.join(self.root_dir, "cli")

    def scaffold(self) -> None:
        section("Subsystem: cli")

        content = textwrap.dedent(
            f"""
            \"\"\"IntentOS CLI wrapper (scaffold).

            Delegates core logic to the root engine:

                {self.engine_path}
            \"\"\"
            import argparse
            import os
            import subprocess
            import sys

            ROOT_ENGINE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "root"))

            def main():
                parser = argparse.ArgumentParser(description="IntentOS CLI (scaffold)")
                parser.add_argument("--status", action="store_true", help="Show basic status")
                parser.add_argument("--raw-root", action="store_true", help="Run root directly with no arguments")

                args, unknown = parser.parse_known_args()

                if args.status:
                    print("IntentOS status: OK (scaffolded CLI)")
                    print(f"Root engine present: {{os.path.exists(ROOT_ENGINE)}} at {{ROOT_ENGINE}}")

                if args.raw_root:
                    if not os.path.exists(ROOT_ENGINE):
                        print("Root engine not found; cannot run.")
                        sys.exit(1)
                    print(f"Running root engine directly: {{ROOT_ENGINE}}")
                    result = subprocess.run(
                        [sys.executable, ROOT_ENGINE, *unknown],
                        text=True
                    )
                    sys.exit(result.returncode)

                if not args.status and not args.raw_root:
                    parser.print_help()

            if __name__ == "__main__":
                main()
            """
        ).strip() + "\n"

        self.ensure_file("cli.py", content, "cli cli.py")

    def smoke(self) -> None:
        section("Smoke test: CLI")
        self.check_file("cli.py", "CLI scaffold present (cli/cli.py).", "CLI not present; skipping CLI smoke test.")
        cli_py = os.path.join(self.path, "cli.py")
        if not os.path.exists(cli_py):
            return

        run_cmd(
            self.ctx,
            [sys.executable, "cli.py", "--status"],
            cwd=self.path,
            allow_fail=True,
            label="CLI smoke (--status)",
        )


class VSCodeExtensionSubsystem(Subsystem):
    name = "vscode_extension"
    description = "VS Code extension scaffold"

    @property
    def path(self) -> str:
        return os.path.join(self.root_dir, "vscode_extension")

    def scaffold(self) -> None:
        section("Subsystem: vscode_extension")

        content = textwrap.dedent(
            """
            {
              "name": "intentos-extension",
              "displayName": "IntentOS Extension",
              "description": "VS Code tools for IntentOS (scaffold)",
              "version": "0.0.1",
              "engines": {
                "vscode": "^1.80.0"
              },
              "activationEvents": [
                "onCommand:intentos.helloWorld"
              ],
              "contributes": {
                "commands": [
                  {
                    "command": "intentos.helloWorld",
                    "title": "IntentOS: Hello World"
                  }
                ]
              },
              "main": "./dist/extension.js"
            }
            """
        ).strip() + "\n"

        self.ensure_file("package.json", content, "VS Code extension package.json")


class ElectronSubsystem(Subsystem):
    name = "electron_app"
    description = "Electron desktop shell"

    @property
    def path(self) -> str:
        return os.path.join(self.root_dir, "electron_app")

    def scaffold(self) -> None:
        section("Subsystem: electron_app")

        pkg_content = textwrap.dedent(
            """
            {
              "name": "intentos-electron",
              "version": "0.0.1",
              "main": "main.js",
              "scripts": {
                "start": "electron ."
              },
              "devDependencies": {
                "electron": "^30.0.0"
              }
            }
            """
        ).strip() + "\n"

        main_content = textwrap.dedent(
            """
            const { app, BrowserWindow } = require('electron');
            const path = require('path');

            function createWindow() {
              const win = new BrowserWindow({
                width: 1200,
                height: 800,
                webPreferences: {
                  preload: path.join(__dirname, 'preload.js')
                }
              });

              win.loadFile(path.join(__dirname, '..', 'dashboard', 'index.html'));
            }

            app.whenReady().then(() => {
              createWindow();

              app.on('activate', () => {
                if (BrowserWindow.getAllWindows().length === 0) createWindow();
              });
            });

            app.on('window-all-closed', () => {
              if (process.platform !== 'darwin') app.quit();
            });
            """
        ).strip() + "\n"

        self.ensure_file("package.json", pkg_content, "Electron package.json")
        self.ensure_file("main.js", main_content, "Electron main.js")

    def launch(self) -> None:
        if not self.ctx.config.auto_launch_electron:
            info("Auto-launch Electron disabled by config; skipping.")
            return

        section("Launching Electron app (if available)")

        package_json = os.path.join(self.path, "package.json")
        if not os.path.exists(package_json):
            warn("Electron package.json not found; cannot launch Electron app.")
            return

        run_cmd(
            self.ctx,
            ["npm", "install"],
            cwd=self.path,
            allow_fail=True,
            label="npm install (electron_app)",
        )

        run_cmd(
            self.ctx,
            ["npm", "run", "start"],
            cwd=self.path,
            allow_fail=True,
            label="npm run start (electron_app)",
            background=True,
        )


class LegalSubsystem(Subsystem):
    name = "legal"
    description = "Licenses and policy placeholders"

    @property
    def path(self) -> str:
        return os.path.join(self.root_dir, "legal")

    def scaffold(self) -> None:
        section("Subsystem: legal")

        files = {
            "LICENSE.txt": "IntentOS License (placeholder). Replace with your real license.\n",
            "PRIVACY_POLICY.txt": "IntentOS Privacy Policy (placeholder). Replace with real policy.\n",
        }
        for name, text in files.items():
            self.ensure_file(name, text, f"legal file {name}")


class ConfigSubsystem(Subsystem):
    name = "config"
    description = "Base configuration"

    @property
    def path(self) -> str:
        return os.path.join(self.root_dir, "config")

    def scaffold(self) -> None:
        section("Subsystem: config")

        content = textwrap.dedent(
            """
            {
              "name": "IntentOS",
              "version": "0.0.1",
              "environment": "dev",
              "services": {
                "backend": {
                  "host": "127.0.0.1",
                  "port": 8000
                }
              }
            }
            """
        ).strip() + "\n"

        self.ensure_file("intentos_config.json", content, "config intentos_config.json")


class MiscSubsystem(Subsystem):
    name = "misc"
    description = "Miscellaneous files / scratch"

    @property
    def path(self) -> str:
        return os.path.join(self.root_dir, "misc")

    def scaffold(self) -> None:
        section("Subsystem: misc")

        content = "Miscellaneous files for IntentOS (logs, experiments, scratchpads, etc.).\n"
        self.ensure_file("README_MISC.md", content, "misc README_MISC.md")


class TestsSubsystem(Subsystem):
    name = "tests"
    description = "Tests and smoke checks"

    @property
    def path(self) -> str:
        return os.path.join(self.root_dir, "tests")

    def scaffold(self) -> None:
        section("Subsystem: tests")

        content = textwrap.dedent(
            """
            def test_smoke():
                # Minimal smoke test to validate that the test pipeline is wired.
                assert True
            """
        ).strip() + "\n"

        self.ensure_file("test_smoke.py", content, "smoke test test_smoke.py")


# ===========================================================================
# Git helpers
# ===========================================================================

def git_available() -> bool:
    try:
        subprocess.run(
            ["git", "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
        return True
    except Exception:
        return False


def git_status_summary(ctx: WizardContext) -> None:
    if not ctx.config.enable_git:
        warn("Git orchestration disabled by config.")
        return
    if not git_available():
        warn("Git not available on PATH; skipping git status.")
        return

    section("Git status summary")
    run_cmd(ctx, ["git", "status", "-sb"], cwd=ctx.config.repo_root, allow_fail=True)


# ===========================================================================
# Orchestrator
# ===========================================================================

class IntentOSEngineBuilder:
    """Main orchestrator for the single-file modular engine."""

    def __init__(self, ctx: WizardContext) -> None:
        self.ctx = ctx
        self.root_manager = RootEngineManager(ctx)
        self.subsystems: List[Subsystem] = []

    def setup_subsystems(self, engine_path: str) -> None:
        """Instantiate all subsystems, wired to the engine."""
        self.subsystems = [
            BackendSubsystem(self.ctx, engine_path),
            DashboardSubsystem(self.ctx),
            CLISubsystem(self.ctx, engine_path),
            VSCodeExtensionSubsystem(self.ctx),
            ElectronSubsystem(self.ctx),
            LegalSubsystem(self.ctx),
            ConfigSubsystem(self.ctx),
            MiscSubsystem(self.ctx),
            TestsSubsystem(self.ctx),
        ]

    def scaffold_all(self) -> None:
        banner("Scaffolding subsystems around root")
        for sub in self.subsystems:
            sub.scaffold()

    def health_summary(self, engine_path: str) -> None:
        banner("Health summary")

        if os.path.exists(engine_path):
            record_action(self.ctx, f"Root engine present at {engine_path}")
        else:
            record_error(self.ctx, f"Root engine missing at {engine_path}")

        for sub in self.subsystems:
            sub.health()

    def smoke_tests(self) -> None:
        for sub in self.subsystems:
            sub.smoke()

    def launch_services(self) -> None:
        for sub in self.subsystems:
            sub.launch()

    def summarize(self) -> None:
        banner("IntentOS Engine Builder Summary")

        print("Actions performed:")
        if self.ctx.actions_log:
            for line in self.ctx.actions_log:
                print(f"  - {line}")
        else:
            print("  (none)")

        print()
        print("Errors:")
        if self.ctx.errors_log:
            for line in self.ctx.errors_log:
                print(f"  - {line}")
        else:
            print("  (none)")

        print()
        info("Engine builder run complete.")


# ===========================================================================
# Entry point
# ===========================================================================

def main() -> None:
    repo_root = os.path.abspath(os.path.dirname(__file__))
    cfg = WizardConfig(
        repo_root=repo_root,
        root_github_raw_url="https://raw.githubusercontent.com/adreinmorin-design/Intentos/main/root",
        root_engine_filename="root",
        default_branch="main",
        enable_git=True,
        auto_launch_backend=True,
        auto_open_dashboard=True,
        auto_launch_electron=False,  # flip to True when you want desktop auto-launch
    )
    ctx = WizardContext(config=cfg)

    banner("IntentOS Engine Builder (single-file modular engine)")

    info(f"Repository root: {repo_root}")
    info(f"Engine source:  {cfg.root_github_raw_url}")
    print()

    builder = IntentOSEngineBuilder(ctx)

    # 1. Always pull latest root from GitHub and overwrite local
    engine_path = builder.root_manager.sync_from_github()

    # 2. Light git status
    git_status_summary(ctx)

    # 3. Setup and scaffold subsystems
    builder.setup_subsystems(engine_path)
    builder.scaffold_all()

    # 4. Health summary
    builder.health_summary(engine_path)

    # 5. Smoke tests
    builder.smoke_tests()

    # 6. Launch backend, dashboard, and optionally Electron
    builder.launch_services()

    # 7. Final summary
    builder.summarize()


if __name__ == "__main__":
    main()