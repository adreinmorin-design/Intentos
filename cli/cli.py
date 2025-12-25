"""IntentOS CLI wrapper (scaffold).

Delegates core logic to the root engine:

    C:\Users\Albert Morin\Documents\Intentos\root
"""
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
        print(f"Root engine present: {os.path.exists(ROOT_ENGINE)} at {ROOT_ENGINE}")

    if args.raw_root:
        if not os.path.exists(ROOT_ENGINE):
            print("Root engine not found; cannot run.")
            sys.exit(1)
        print(f"Running root engine directly: {ROOT_ENGINE}")
        result = subprocess.run(
            [sys.executable, ROOT_ENGINE, *unknown],
            text=True
        )
        sys.exit(result.returncode)

    if not args.status and not args.raw_root:
        parser.print_help()

if __name__ == "__main__":
    main()
