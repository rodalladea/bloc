"""Fresh-runner startup and Python import isolation regressions."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import threading
import unittest

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts/distribution'


class StartupTests(unittest.TestCase):
    def test_distribution_path_preserves_stdlib_platform(self):
        result = subprocess.run([
            sys.executable, '-c',
            'import sys; sys.path.insert(0, sys.argv[1]); import platform; '
            'assert callable(platform.system); print(platform.system())', str(SCRIPTS),
        ], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.strip())

    def test_registry_waits_for_api_and_fails_if_unavailable(self):
        sys.path.insert(0, str(SCRIPTS))
        from wait_registry import wait_ready

        class Handler(BaseHTTPRequestHandler):
            requests = 0
            ready = False

            def do_GET(self):
                type(self).requests += 1
                status = 200 if self.ready and self.requests >= 3 else 503
                self.send_response(status if self.path == '/v2/' else 404)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f'http://127.0.0.1:{server.server_port}/v2/'
            Handler.ready = True
            wait_ready(url, timeout=2, interval=0.01)
            self.assertGreaterEqual(Handler.requests, 3)
            Handler.ready = False
            with self.assertRaisesRegex(TimeoutError, 'registry API did not become ready'):
                wait_ready(url, timeout=0.05, interval=0.01)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    unittest.main(verbosity=2)
