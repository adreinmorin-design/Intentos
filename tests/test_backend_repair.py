import os
import time
import tempfile
import signal
import json
from gui_intentos.gui_intentos import IntentOSPaths, attempt_backend_restart


def make_simple_backend(path):
    # create a simple HTTP server script with /health
    code = r'''
import http.server
import socketserver
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')
        else:
            super().do_GET()

if __name__ == '__main__':
    import sys
    import os
    os.chdir(os.path.dirname(__file__))
    with socketserver.TCPServer(('127.0.0.1', 8000), Handler) as httpd:
        httpd.serve_forever()
'''
    with open(path, 'w', encoding='utf-8') as f:
        f.write(code)


def test_attempt_backend_restart_starts_simple_server():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        backend_dir = os.path.join(paths.repo_root, 'backend')
        os.makedirs(backend_dir, exist_ok=True)
        backend_main = os.path.join(backend_dir, 'main.py')
        make_simple_backend(backend_main)
        # ensure paths attribute matches
        paths.backend_main = backend_main

        ok, report = attempt_backend_restart(paths, timeout=6)
        assert ok is True, f"Backend did not start: {report}"

        # cleanup: kill process if pid file exists
        try:
            if os.path.exists(paths.backend_pid_file):
                with open(paths.backend_pid_file, 'r', encoding='utf-8') as f:
                    pid = int(f.read().strip())
                try:
                    os.kill(pid, signal.SIGTERM)
                except Exception:
                    pass
                # wait until /health stops responding or timeout
                import urllib.request, urllib.error
                for _ in range(10):
                    try:
                        with urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=1) as r:
                            # still up
                            time.sleep(0.2)
                            try:
                                os.kill(pid, signal.SIGTERM)
                            except Exception:
                                pass
                    except Exception:
                        break
        except Exception:
            pass
