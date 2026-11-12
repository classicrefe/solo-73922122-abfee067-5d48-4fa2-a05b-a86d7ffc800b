"""Process isolation, slot accounting and lifecycle of one scan request.

The web process delegates every scan to an independent worker subprocess
(:mod:`app.worker`).  This module makes that delegation safe:

* A single global :class:`SlotPool` caps concurrent scans (upload scans and
  built-in demo scans share the slots).  When every slot is busy the request
  fails immediately with HTTP 503 -- it never queues.
* After a slot is granted, the worker has ``SCAN_TIMEOUT_SECONDS`` (default
  three seconds) to finish; otherwise the whole process group is killed and
  the request fails with HTTP 504.
* Client disconnects (browser cancel button, closed tab, dropped TCP
  connection) terminate the worker in the same way as a timeout.
* The slot is released *only after* the worker process has been reaped, its
  pipes are closed and this request's private staging directory is removed.
  Each request gets its own fresh empty directory, so cleanup can never touch
  another request's files.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import shutil
import signal
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

PACKAGE_PARENT = Path(__file__).resolve().parent.parent

# How long we wait for SIGTERM to take effect before escalating to SIGKILL.
_TERM_GRACE_SECONDS = 2.0
# Pipe drain after process exit should be immediate EOF; this is just a guard.
_PIPE_DRAIN_SECONDS = 5.0
_UPLOAD_CHUNK = 1024 * 1024


class ScanTimeout(Exception):
    """The worker did not finish within the configured time budget."""


class ScanCancelled(Exception):
    """The HTTP client went away while the scan was running."""


class ScanJobFailed(Exception):
    """The worker reported a structured failure or crashed."""

    def __init__(self, *, status_code: int, detail: dict) -> None:
        super().__init__(detail.get("message", "scan failed"))
        self.status_code = status_code
        self.detail = detail


@dataclass(frozen=True)
class ScanConfig:
    capacity: int
    timeout_seconds: float
    worker_delay_seconds: float
    tmp_dir: str

    @classmethod
    def from_env(cls) -> "ScanConfig":
        return cls(
            capacity=int(os.environ.get("SCAN_MAX_SLOTS", "2")),
            timeout_seconds=float(os.environ.get("SCAN_TIMEOUT_SECONDS", "3.0")),
            worker_delay_seconds=float(os.environ.get("SCAN_WORKER_DELAY_SECONDS", "0")),
            tmp_dir=os.environ.get("SCAN_TMP_DIR") or tempfile.gettempdir(),
        )


class SlotPool:
    """Instant-admission semaphore: no waiters, no queue."""

    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("slot capacity must be at least one")
        self.capacity = capacity
        self._free = capacity
        self._in_use = 0
        self._lock = asyncio.Lock()

    async def try_acquire(self) -> bool:
        async with self._lock:
            if self._free == 0:
                return False
            self._free -= 1
            self._in_use += 1
            return True

    async def release(self) -> None:
        async with self._lock:
            if self._in_use == 0:
                # Defensive: a programming error here must never inflate the
                # pool beyond its real capacity.
                raise RuntimeError("released a scan slot that was not held")
            self._free += 1
            self._in_use -= 1

    def snapshot(self) -> dict:
        return {
            "capacity": self.capacity,
            "in_use": self._in_use,
            "available": self._free,
        }


def _worker_env() -> dict[str, str]:
    # A small, explicit environment.  ``python -I`` already ignores
    # PYTHONPATH/PYTHONHOME and user site-packages; we still avoid forwarding
    # unrelated variables into the untrusted-archive worker process.
    allow = ("PATH", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE")
    env = {key: os.environ[key] for key in allow if key in os.environ}
    env.setdefault("PATH", "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin")
    env.setdefault("TMPDIR", tempfile.gettempdir())
    return env


class ScanSupervisor:
    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig.from_env()
        self.pool = SlotPool(self.config.capacity)

    def create_job(self, *, source: str) -> "ScanJob":
        return ScanJob(self, source=source)


class ScanJob:
    """One request's subprocess, staging directory and slot reservation."""

    def __init__(self, supervisor: ScanSupervisor, *, source: str) -> None:
        self._supervisor = supervisor
        self._source = source
        self._staging_dir = Path(
            tempfile.mkdtemp(prefix=f"scan-{uuid.uuid4().hex}-", dir=supervisor.config.tmp_dir)
        )
        self._archive_path = self._staging_dir / "archive.tar"
        self._slot_held = False
        self._process: asyncio.subprocess.Process | None = None
        self._closed = False

    @property
    def staging_dir(self) -> Path:
        return self._staging_dir

    async def stage_upload(self, request, upload) -> None:
        """Spool the upload into this request's private staging directory.

        The bytes are only *staged* for the scanner subprocess; the archive and
        its layers are never unpacked.  A disconnect while spooling aborts the
        upload immediately.
        """

        with open(self._archive_path, "wb") as destination:
            while True:
                disconnected = await request.is_disconnected()
                chunk = await upload.read(_UPLOAD_CHUNK)
                if disconnected:
                    raise ScanCancelled()
                if not chunk:
                    break
                await asyncio.to_thread(destination.write, chunk)
                await asyncio.to_thread(destination.flush)

    async def acquire_slot(self) -> bool:
        granted = await self._supervisor.pool.try_acquire()
        self._slot_held = granted
        return granted

    async def execute(self, request) -> dict:
        """Run the worker subprocess and return the scan payload on success."""

        if not self._slot_held:
            raise RuntimeError("scan executed without holding a compute slot")

        argv = [
            sys.executable,
            "-I",
            str(PACKAGE_PARENT / "app" / "worker.py"),
            "--source",
            self._source,
        ]
        if self._source == "upload":
            argv += ["--input", str(self._archive_path)]
        # The diagnostic delay is a demo-scan hook only: real upload scans
        # must never be artificially slowed.
        if self._source == "built-in-demo":
            delay = self._supervisor.config.worker_delay_seconds
            if delay > 0:
                argv += ["--delay", str(delay)]

        self._process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(PACKAGE_PARENT),
            env=_worker_env(),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            # New session => own process group, so killing the group removes
            # every descendant, not just the Python interpreter.
            start_new_session=True,
        )

        outcome = await self._race_outcomes(request)
        if outcome == "cancelled":
            await self._terminate_and_reap()
            await self._drain_pipes()
            raise ScanCancelled()
        if outcome == "timeout":
            await self._terminate_and_reap()
            await self._drain_pipes()
            raise ScanTimeout()

        # Natural completion: make sure the process is fully reaped.
        await self._wait_process()
        stdout_bytes, stderr_bytes = await self._drain_pipes()
        return self._interpret(stdout_bytes, stderr_bytes)

    async def _watch_disconnect(self, request) -> None:
        """Poll the ASGI receive channel until the client disconnects.

        ``Request.is_disconnected()`` is an instant one-shot probe, so it must
        be polled in a loop rather than raced a single time.
        """

        while True:
            if await request.is_disconnected():
                return
            await asyncio.sleep(0.1)

    async def _race_outcomes(self, request) -> str:
        proc = self._process
        assert proc is not None
        done_task = asyncio.create_task(proc.wait())
        disconnect_task = asyncio.create_task(self._watch_disconnect(request))
        try:
            await asyncio.wait(
                {done_task, disconnect_task},
                timeout=self._supervisor.config.timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
        except asyncio.TimeoutError:
            return "timeout"
        finally:
            if not done_task.done():
                done_task.cancel()
            if not disconnect_task.done():
                disconnect_task.cancel()
            # Swallow CancelledError from the tasks we just cancelled.
            for task in (done_task, disconnect_task):
                if not task.done():
                    with contextlib.suppress(asyncio.CancelledError):
                        await task

        if disconnect_task.done() and not disconnect_task.cancelled():
            return "cancelled"
        if done_task.done() and not done_task.cancelled():
            return "completed"
        # asyncio.wait returned because the timeout elapsed without a winner.
        return "timeout"

    async def _wait_process(self) -> None:
        proc = self._process
        assert proc is not None
        if proc.returncode is None:
            await proc.wait()

    async def _terminate_and_reap(self) -> None:
        proc = self._process
        assert proc is not None
        if proc.returncode is not None:
            return
        try:
            # New session => own process group, so this reaches every
            # descendant, not just the Python interpreter.
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        except PermissionError:
            # Hardened sandboxes may deny kill(2); fall through to SIGKILL /
            # pipe closure below instead of leaving the job wedged.
            logger.warning("SIGTERM denied for scan worker %s", proc.pid)
        try:
            await asyncio.wait_for(proc.wait(), timeout=_TERM_GRACE_SECONDS)
            return
        except asyncio.TimeoutError:
            logger.warning("scan worker %s ignored SIGTERM; sending SIGKILL", proc.pid)
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        except PermissionError:
            # No signal privilege at all: closing the pipes makes any further
            # worker write fail, and the event loop still reaps the process
            # when it exits.
            logger.warning("SIGKILL denied for scan worker %s; closing pipes", proc.pid)
            for stream in (proc.stdout, proc.stderr):
                if stream is None:
                    continue
                transport = getattr(stream, "_transport", None)
                if transport is not None:
                    transport.close()
        await proc.wait()

    async def _drain_pipes(self) -> tuple[bytes, bytes]:
        proc = self._process
        assert proc is not None
        chunks: list[bytes] = []
        for stream in (proc.stdout, proc.stderr):
            if stream is None:
                chunks.append(b"")
                continue
            try:
                chunks.append(await asyncio.wait_for(stream.read(), timeout=_PIPE_DRAIN_SECONDS))
            except asyncio.TimeoutError:  # pragma: no cover - defensive guard
                chunks.append(b"")
            # StreamReader itself has no close(); shut the transport down so
            # the kernel file descriptors are released.
            transport = getattr(stream, "_transport", None)
            if transport is not None:
                transport.close()
        return chunks[0], chunks[1]

    def _interpret(self, stdout_bytes: bytes, stderr_bytes: bytes) -> dict:
        proc = self._process
        assert proc is not None
        if proc.returncode != 0:
            logger.warning(
                "scan worker exited with %s: %s",
                proc.returncode,
                stderr_bytes.decode("utf-8", "replace")[-2000:],
            )
            raise ScanJobFailed(
                status_code=500,
                detail={
                    "code": "worker_crashed",
                    "message": f"扫描进程异常退出（退出码 {proc.returncode}）",
                },
            )

        try:
            payload = json_from_bytes(stdout_bytes)
        except ValueError:
            logger.warning(
                "scan worker returned unparseable output: %s",
                stderr_bytes.decode("utf-8", "replace")[-2000:],
            )
            raise ScanJobFailed(
                status_code=500,
                detail={"code": "worker_crashed", "message": "扫描进程没有返回有效结果"},
            )

        if payload.get("status") == "ok" and isinstance(payload.get("result"), dict):
            return payload["result"]

        error = payload.get("error") if isinstance(payload, dict) else None
        if isinstance(error, dict) and error.get("type") == "scan_error":
            detail = error.get("detail")
            if isinstance(detail, dict) and "code" in detail:
                raise ScanJobFailed(status_code=400, detail=detail)
        raise ScanJobFailed(
            status_code=500,
            detail={
                "code": "scan_failed",
                "message": (
                    isinstance(error, dict)
                    and isinstance(error.get("detail"), dict)
                    and error["detail"].get("message")
                )
                or "扫描失败：worker_failure",
            },
        )

    async def close(self) -> None:
        """Guaranteed teardown; safe to call from a ``finally`` block.

        Order matters: reap the worker first, close its pipes, remove the
        staging directory, and only then give the slot back.  Every step is
        scoped to this job, so another request's resources are untouched.
        """

        if self._closed:
            return
        self._closed = True

        if self._process is not None:
            with contextlib.suppress(Exception):
                await self._terminate_and_reap()
            with contextlib.suppress(Exception):
                await self._drain_pipes()

        await asyncio.to_thread(shutil.rmtree, self._staging_dir, ignore_errors=True)

        if self._slot_held:
            await self._supervisor.pool.release()
            self._slot_held = False


def json_from_bytes(raw: bytes) -> dict:
    # The worker writes exactly one JSON document on its last line.
    text = raw.decode("utf-8", "replace").strip()
    if not text:
        raise ValueError("empty worker output")
    return json.loads(text.splitlines()[-1])
