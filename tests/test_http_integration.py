"""End-to-end HTTP tests against a real single-process uvicorn server.

The server runs in a background thread of this test process so it shares no
test-only shortcuts: requests go over a real TCP socket, multipart bodies are
real uploads, and client disconnects are real socket closes.  Only the Python
standard library is used.
"""

from __future__ import annotations

import contextlib
import http.client
import io
import json
import os
import socket
import tempfile
import threading
import time
import unittest
import uuid

import uvicorn

from app.sample import build_demo_archive

HOST = "127.0.0.1"
# Short, explicit time budget so the suite stays fast.  Production default is 3s.
TIMEOUT_SECONDS = "1.0"
# Workers outlive the timeout so 504/503 paths are exercised, but stay short:
# even on hosts whose seccomp filter denies kill(2), the self-terminating
# worker (parent-death watchdog / interruptible sleep) exits within this window.
WORKER_DELAY_SECONDS = "2.0"
# How long to wait for a sandbox-blocked worker to self-exit.
SLOT_SETTLE_TIMEOUT = 6.0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


class _ServerThread(threading.Thread):
    def __init__(self, port: int, tmp_dir: str) -> None:
        super().__init__(daemon=True)
        self.port = port
        self.tmp_dir = tmp_dir
        self.ready = threading.Event()
        self.server: uvicorn.Server | None = None

    def run(self) -> None:
        # Configure the supervisor before the app module is imported; env vars
        # are process-global and read once at ScanSupervisor construction.
        os.environ["SCAN_MAX_SLOTS"] = "2"
        os.environ["SCAN_TIMEOUT_SECONDS"] = TIMEOUT_SECONDS
        os.environ["SCAN_WORKER_DELAY_SECONDS"] = WORKER_DELAY_SECONDS
        os.environ["SCAN_TMP_DIR"] = self.tmp_dir

        from app.main import app  # imported after env configuration

        config = uvicorn.Config(
            app,
            host=HOST,
            port=self.port,
            workers=1,
            log_level="warning",
            lifespan="on",
        )
        self.server = uvicorn.Server(config)
        self.server.install_signal_handlers = lambda: None  # don't touch test signals
        self.ready.set()
        self.server.run()

    def stop(self) -> None:
        if self.server is not None:
            self.server.should_exit = True


def _multipart_body(field: str, filename: str, payload: bytes) -> tuple[bytes, str]:
    boundary = f"----scan-test-{uuid.uuid4().hex}"
    body = io.BytesIO()
    body.write(f"--{boundary}\r\n".encode())
    body.write(
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'.encode()
    )
    body.write(b"Content-Type: application/x-tar\r\n\r\n")
    body.write(payload)
    body.write(f"\r\n--{boundary}--\r\n".encode())
    return body.getvalue(), boundary


def _request(
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    content_type: str | None = None,
    timeout: float = 10.0,
) -> tuple[int, bytes, dict]:
    conn = http.client.HTTPConnection(HOST, port, timeout=timeout)
    headers = {"Accept": "application/json"}
    if content_type:
        headers["Content-Type"] = content_type
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        payload = response.read()
        return response.status, payload, dict(response.headers)
    finally:
        conn.close()


class HttpIntegrationTests(unittest.TestCase):
    server_thread: _ServerThread
    port: int
    tmp_dir: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.port = _free_port()
        cls.tmp_dir = tempfile.mkdtemp(prefix="scan-http-")
        cls.server_thread = _ServerThread(cls.port, cls.tmp_dir)
        cls.server_thread.start()
        cls.server_thread.ready.wait(5)
        cls._wait_until_ready()

    @classmethod
    def _wait_until_ready(cls, attempts: int = 50) -> None:
        for _ in range(attempts):
            try:
                with socket.create_connection((HOST, cls.port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("test uvicorn server never became ready")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server_thread.stop()
        cls.server_thread.join(timeout=10)

    def setUp(self) -> None:
        # Workers from a previous test can briefly outlive it on hosts whose
        # seccomp filter denies kill(2); never start a test with a busy slot.
        self._wait_for_slots(0, timeout=SLOT_SETTLE_TIMEOUT + 4.0)

    def _get_json(self, path: str, timeout: float = 10.0) -> tuple[int, dict]:
        status, raw, _ = _request(self.port, "GET", path, timeout=timeout)
        return status, json.loads(raw.decode("utf-8")) if raw else {}

    def _post_upload(self, path: str, field: str, filename: str,
                     payload: bytes) -> tuple[int, dict]:
        body, boundary = _multipart_body(field, filename, payload)
        status, raw, _headers = _request(
            self.port, "POST", path,
            body=body,
            content_type=f"multipart/form-data; boundary={boundary}",
            timeout=10,
        )
        return status, json.loads(raw.decode("utf-8")) if raw else {}

    def test_01_healthz_reports_slot_snapshot(self) -> None:
        status, payload = self._get_json("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(
            payload["slots"], {"capacity": 2, "in_use": 0, "available": 2}
        )

    def test_02_index_and_static_assets_served(self) -> None:
        status, raw, _ = _request(self.port, "GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"<!doctype html>", raw)
        status, raw, _ = _request(self.port, "GET", "/static/app.js")
        self.assertEqual(status, 200)
        self.assertIn(b"cancel-button", raw)

    def test_03_demo_archive_download_never_consumes_a_slot(self) -> None:
        status, payload, headers = _request(self.port, "GET", "/api/demo/archive")
        self.assertEqual(status, 200)
        self.assertEqual(
            headers.get("Content-Type") or headers.get("content-type"),
            "application/x-tar",
        )
        # Deterministic demo bytes, matching the packaged example archive.
        self.assertEqual(payload, build_demo_archive())
        _, health = self._get_json("/healthz")
        self.assertEqual(health["slots"]["in_use"], 0)

    def test_04_missing_file_is_400(self) -> None:
        status, _, _ = _request(
            self.port, "POST", "/api/scan", body=b"",
            content_type="multipart/form-data; boundary=xx",
        )
        self.assertEqual(status, 400)

    def test_05_invalid_archive_returns_400_no_partial_results(self) -> None:
        status, payload = self._post_upload(
            "/api/scan", "archive", "bad.tar", b"not a tar at all"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["detail"]["code"], "archive_invalid")
        # Only result key on failure is the error detail.
        self.assertNotIn("files", payload)
        _, health = self._get_json("/healthz")
        self.assertEqual(health["slots"]["in_use"], 0)

    def test_06_full_capacity_returns_503_immediately(self) -> None:
        sockets: list[socket.socket] = []
        try:
            # Occupy both slots with long-lived demo scans.
            for _ in range(2):
                sock = socket.create_connection((HOST, self.port), timeout=5)
                sockets.append(sock)
                sock.sendall(b"GET /api/demo HTTP/1.1\r\nHost: x\r\n\r\n")
            self._wait_for_slots_at_least(2)

            status, raw, headers = _request(
                self.port, "GET", "/api/demo", timeout=5
            )
            payload = json.loads(raw.decode("utf-8"))
            self.assertEqual(status, 503)
            self.assertEqual(payload["detail"]["code"], "capacity_full")
            self.assertEqual(
                headers.get("Retry-After") or headers.get("retry-after"), "1"
            )
        finally:
            for sock in sockets:
                with contextlib.suppress(OSError):
                    sock.close()
        self._wait_for_slots(0)

    def test_07_timeout_returns_504_and_releases_slot(self) -> None:
        started = time.monotonic()
        status, raw, _ = _request(self.port, "GET", "/api/demo", timeout=10)
        payload = json.loads(raw.decode("utf-8"))
        elapsed = time.monotonic() - started
        self.assertEqual(status, 504)
        self.assertEqual(payload["detail"]["code"], "scan_timeout")
        self.assertGreaterEqual(elapsed, float(TIMEOUT_SECONDS) - 0.1)
        self._wait_for_slots(0)

        # Staging directories created for timed-out jobs are removed.
        leftovers = [
            name for name in os.listdir(self.tmp_dir) if name.startswith("scan-")
        ]
        self.assertEqual(leftovers, [])

    def test_08_client_disconnect_terminates_scan_and_frees_slot(self) -> None:
        sock = socket.create_connection((HOST, self.port), timeout=5)
        try:
            sock.sendall(b"GET /api/demo HTTP/1.1\r\nHost: x\r\n\r\n")
            self._wait_for_slots_at_least(1)
            # Abrupt HTTP disconnect: the server must notice and kill the job.
            sock.close()
            self._wait_for_slots(0)
        finally:
            with contextlib.suppress(OSError):
                sock.close()

    def test_09_upload_disconnect_mid_body_does_not_hold_a_slot(self) -> None:
        body, boundary = _multipart_body("archive", "big.tar", b"x" * (4 * 1024 * 1024))
        sock = socket.create_connection((HOST, self.port), timeout=5)
        try:
            sock.sendall(
                (
                    f"POST /api/scan HTTP/1.1\r\nHost: x\r\n"
                    f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n"
                ).encode()
            )
            sock.sendall(body[: 512 * 1024])
            sock.close()
            # The abandoned upload must be cleaned up and no slot stuck.
            self._wait_for_slots(0)
        finally:
            with contextlib.suppress(OSError):
                sock.close()

    def test_10_health_and_downloads_stay_responsive_while_scans_run(self) -> None:
        sockets: list[socket.socket] = []
        try:
            for _ in range(2):
                sock = socket.create_connection((HOST, self.port), timeout=5)
                sockets.append(sock)
                sock.sendall(b"GET /api/demo HTTP/1.1\r\nHost: x\r\n\r\n")
            self._wait_for_slots_at_least(2)

            status, health = self._get_json("/healthz")
            self.assertEqual(status, 200)
            self.assertEqual(health["slots"]["in_use"], 2)

            status, raw, _ = _request(self.port, "GET", "/")
            self.assertEqual(status, 200)
            self.assertTrue(raw)

            status, payload, _ = _request(self.port, "GET", "/api/demo/archive")
            self.assertEqual(status, 200)
            self.assertTrue(payload)
        finally:
            for sock in sockets:
                with contextlib.suppress(OSError):
                    sock.close()
            self._wait_for_slots(0)

    def test_11_legacy_scan_route_uses_same_guard(self) -> None:
        # The diagnostic delay only applies to demo-source jobs, so this
        # upload scans immediately.
        status, payload = self._post_upload(
            "/scan", "file", "demo.tar", build_demo_archive()
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["summary"]["privileged_files"], 5)

    def test_12_upload_scan_succeeds_with_full_result_shape(self) -> None:
        status, payload = self._post_upload(
            "/api/scan", "archive", "multilayer-demo.tar", build_demo_archive()
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["source"], "upload")
        self.assertEqual(payload["summary"], {
            "layers_scanned": 4,
            "privileged_files": 5,
            "suid_files": 2,
            "sgid_files": 3,
        })
        self.assertEqual(
            [item["path"] for item in payload["files"]],
            [
                "/opt/tools/legacy/newhelper",
                "/usr/bin/ping",
                "/usr/bin/wall",
                "/usr/local/bin/oldtool/wrapper",
                "/var/lib/cache",
            ],
        )
        self._wait_for_slots(0)

    def _wait_for_slots(self, in_use: int, timeout: float = SLOT_SETTLE_TIMEOUT) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                _, health = self._get_json("/healthz", timeout=3)
                if health["slots"]["in_use"] == in_use:
                    return
            except (http.client.HTTPException, OSError):
                pass
            time.sleep(0.15)
        raise AssertionError(f"slots.in_use never reached {in_use}")

    def _wait_for_slots_at_least(self, minimum: int,
                                 timeout: float = SLOT_SETTLE_TIMEOUT) -> None:
        """Wait until at least ``minimum`` slots are occupied.

        A busy slot can pass quickly, so equality polling can miss it.
        """

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                _, health = self._get_json("/healthz", timeout=3)
                if health["slots"]["in_use"] >= minimum:
                    return
            except (http.client.HTTPException, OSError):
                pass
            time.sleep(0.1)
        raise AssertionError(f"slots.in_use never reached at least {minimum}")


if __name__ == "__main__":
    unittest.main()
