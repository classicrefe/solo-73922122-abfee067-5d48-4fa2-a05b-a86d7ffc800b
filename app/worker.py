"""Killable scan worker.

This module is the entry point of an *independent* operating-system process
that performs exactly one archive scan and then exits.  The web process never
runs the (potentially unbounded) tar merge itself: it spawns this worker and
can terminate the whole process group when the request is cancelled or times
out, so a malicious deep-path archive can no longer keep a Python thread busy
after the client went away.

Contract
--------
* Invoked by the supervisor as ``python -I /path/to/app/worker.py``.
* argv: ``--input PATH --source upload|built-in-demo [--delay SECONDS]``
* stdin is not used.
* Exactly one JSON document is written to stdout on completion:
  ``{"status": "ok", "result": {...}}`` or
  ``{"status": "error", "error": {...}}``.
* The process exits ``0`` after writing its document.  Any other exit means
  the worker crashed or was killed and the partial output (if any) is ignored.

The worker still never extracts an archive: it reads tar headers only, using
the same :mod:`app.merger` scanner as before.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path

# The supervisor launches this file by path with ``python -I``, so neither
# cwd nor PYTHONPATH is on ``sys.path``; add the package parent explicitly.
_PACKAGE_PARENT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_PARENT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_PARENT))

from app.merger import ScanError, scan_docker_archive  # noqa: E402
from app.sample import build_demo_archive  # noqa: E402


def _emit(payload: dict) -> None:
    """Write the single response document and flush it before exit."""

    sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.write("\n")
    sys.stdout.flush()


def _scan_error_payload(exc: ScanError) -> dict:
    return {
        "status": "error",
        "error": {
            "type": "scan_error",
            "detail": exc.to_detail(),
        },
    }


def _interruptible_sleep(seconds: float) -> None:
    """Sleep in short slices, exiting early on SIGTERM or parent death.

    The diagnostic delay is also a watchdog: if the supervisor disappeared
    without being able to deliver a signal (some hardened sandboxes filter
    ``kill(2)``), the worker must not keep burning CPU on an untrusted archive.
    """

    deadline = time.monotonic() + seconds
    parent_pid = os.getppid()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        if os.getppid() != parent_pid or os.getppid() == 1:
            # Re-parented to PID 1: the web process that owned us is gone.
            os._exit(143)
        time.sleep(min(0.1, remaining))


def _start_parent_death_watchdog() -> None:
    """Exit automatically if the owning web process terminates.

    Belt-and-braces for environments where the supervisor cannot deliver
    SIGTERM/SIGKILL.  The thread is daemon-only and never touches the scan.
    """

    parent_pid = os.getppid()

    def _watch() -> None:  # pragma: no cover - exercised via lifecycle tests
        while True:
            time.sleep(0.2)
            if os.getppid() != parent_pid or os.getppid() == 1:
                os._exit(143)

    thread = threading.Thread(target=_watch, name="parent-death-watch", daemon=True)
    thread.start()


def run(input_path: str, source: str, delay: float) -> dict:
    # Test/diagnostic hook: keep the worker alive so timeout and cancellation
    # paths can be exercised deterministically.  Defaults to zero in
    # production and never touches the archive bytes.
    if delay > 0:
        _interruptible_sleep(delay)

    if source == "built-in-demo":
        result = scan_docker_archive(io.BytesIO(build_demo_archive()))
    else:
        with open(input_path, "rb") as handle:
            result = scan_docker_archive(handle)

    return {"status": "ok", "result": result.as_dict(source=source)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one killable archive scan.")
    parser.add_argument("--input", default="", help="staged archive path (upload scans)")
    parser.add_argument(
        "--source",
        default="upload",
        choices=("upload", "built-in-demo"),
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="sleep before scanning (diagnostics/tests only)",
    )
    args = parser.parse_args(argv)

    # Termination must be prompt and must not run unrelated destructors.  The
    # supervisor first sends SIGTERM and escalates to SIGKILL if needed.
    signal.signal(signal.SIGTERM, lambda _signum, _frame: os._exit(143))

    # Defense in depth when signal delivery is unavailable: die with the
    # web process that spawned this one-shot worker.
    _start_parent_death_watchdog()

    try:
        payload = run(args.input, args.source, max(0.0, args.delay))
    except ScanError as exc:
        payload = _scan_error_payload(exc)
    except Exception as exc:  # defensive: never leak a traceback to the client
        payload = {
            "status": "error",
            "error": {
                "type": "worker_failure",
                "detail": {
                    "code": "scan_failed",
                    "message": f"扫描失败：{type(exc).__name__}",
                },
            },
        }

    _emit(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
