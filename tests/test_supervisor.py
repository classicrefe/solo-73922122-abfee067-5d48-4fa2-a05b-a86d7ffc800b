"""Supervisor lifecycle tests: slots, timeouts, cancellation and cleanup.

These tests exercise the real subprocess machinery (real ``app.worker``
processes) without needing a running HTTP server.  They use only the standard
library so they run in the same minimal environment as the merger tests.
"""

from __future__ import annotations

import asyncio
import io
import os
import tempfile
import time
import unittest
from pathlib import Path

from app.sample import build_demo_archive
from app.supervisor import (
    ScanCancelled,
    ScanConfig,
    ScanJobFailed,
    ScanSupervisor,
    ScanTimeout,
)


class FakeUpload:
    """Minimal UploadFile-like object backed by an in-memory byte string."""

    def __init__(self, payload: bytes, *, stall_after: int = 0) -> None:
        self._buffer = io.BytesIO(payload)
        self._disconnected = False
        self._stall_after = stall_after
        self._delivered = 0

    async def read(self, size: int) -> bytes:
        await asyncio.sleep(0)
        if self._disconnected:
            return b""
        # Bound each read so a disconnect between chunks is actually visible.
        chunk = self._buffer.read(min(size, 256 * 1024))
        self._delivered += len(chunk)
        if self._stall_after and self._delivered >= self._stall_after and chunk:
            # Simulate a slow client: pause once mid-stream so the test can
            # flip the disconnect flag before spooling another chunk.
            self._stall_after = 0
            for _ in range(10):
                await asyncio.sleep(0.02)
        return chunk

    async def is_disconnected(self) -> bool:
        await asyncio.sleep(0)
        return self._disconnected

    def disconnect(self) -> None:
        self._disconnected = True

    async def close(self) -> None:
        self._buffer.close()

class FakeRequest:
    def __init__(self) -> None:
        self._disconnected = False

    async def is_disconnected(self) -> bool:
        await asyncio.sleep(0)
        return self._disconnected

    def disconnect(self) -> None:
        self._disconnected = True


def make_supervisor(tmp_dir: str, *, capacity: int = 2, timeout: float = 3.0,
                    delay: float = 0.0) -> ScanSupervisor:
    return ScanSupervisor(
        ScanConfig(
            capacity=capacity,
            timeout_seconds=timeout,
            worker_delay_seconds=delay,
            tmp_dir=tmp_dir,
        )
    )


class DemoSuccessTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp(prefix="scan-test-")
        self.supervisor = make_supervisor(self._tmp)

    async def test_demo_scan_succeeds_in_subprocess(self) -> None:
        job = self.supervisor.create_job(source="built-in-demo")
        try:
            self.assertTrue(await job.acquire_slot())
            result = await job.execute(FakeRequest())
        finally:
            await job.close()

        self.assertEqual(result["source"], "built-in-demo")
        self.assertEqual(result["summary"]["layers_scanned"], 4)
        self.assertEqual(result["summary"]["privileged_files"], 5)
        self.assertEqual(result["summary"]["suid_files"], 2)
        self.assertEqual(result["summary"]["sgid_files"], 3)

    async def test_staging_directory_removed_and_slot_released(self) -> None:
        job = self.supervisor.create_job(source="built-in-demo")
        staging = job.staging_dir
        self.assertTrue(staging.is_dir())
        self.assertEqual(self.supervisor.pool.snapshot()["in_use"], 0)

        await job.acquire_slot()
        self.assertEqual(self.supervisor.pool.snapshot()["in_use"], 1)
        await job.execute(FakeRequest())
        await job.close()

        self.assertFalse(staging.exists())
        self.assertEqual(self.supervisor.pool.snapshot()["in_use"], 0)
        self.assertEqual(self.supervisor.pool.snapshot()["available"], 2)

    async def test_upload_scan_uses_staged_bytes_without_unpacking(self) -> None:
        payload = build_demo_archive()
        job = self.supervisor.create_job(source="upload")
        try:
            await job.stage_upload(FakeRequest(), FakeUpload(payload))
            staged = job.staging_dir / "archive.tar"
            self.assertTrue(staged.is_file())
            self.assertEqual(staged.stat().st_size, len(payload))
            # Only the single staged archive exists -- nothing was unpacked.
            self.assertEqual(sorted(p.name for p in job.staging_dir.iterdir()),
                             ["archive.tar"])
            await job.acquire_slot()
            result = await job.execute(FakeRequest())
        finally:
            await job.close()
        self.assertEqual(result["summary"]["privileged_files"], 5)


class CapacityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp(prefix="scan-test-")
        # Two slots; workers sleep so both can be held concurrently.
        self.supervisor = make_supervisor(self._tmp, capacity=2, delay=1.5)

    async def test_full_capacity_rejects_immediately_without_queueing(self) -> None:
        request = FakeRequest()
        jobs = [
            self.supervisor.create_job(source="built-in-demo") for _ in range(2)
        ]
        try:
            for job in jobs:
                self.assertTrue(await job.acquire_slot())

            # One slow worker holds a slot; the other slot is already reserved.
            runner = asyncio.create_task(jobs[0].execute(request))
            await asyncio.sleep(0.4)
            self.assertEqual(self.supervisor.pool.snapshot()["available"], 0)

            third = self.supervisor.create_job(source="built-in-demo")
            started = time.monotonic()
            granted = await third.acquire_slot()
            elapsed = time.monotonic() - started
            self.assertFalse(granted)
            # Immediate refusal, not even a short queue wait.
            self.assertLess(elapsed, 0.25)
            await third.close()

            await runner
        finally:
            for job in jobs:
                await job.close()

        self.assertEqual(self.supervisor.pool.snapshot()["available"], 2)


class TimeoutTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp(prefix="scan-test-")

    async def test_timeout_kills_worker_and_cleans_up(self) -> None:
        # Delay exceeds the timeout but stays short: even on hosts where
        # kill(2) is filtered (seccomp sandboxes), the worker finishes quickly
        # and the supervisor still reaps it before releasing the slot.
        supervisor = make_supervisor(self._tmp, timeout=0.5, delay=1.2)
        job = supervisor.create_job(source="built-in-demo")
        staging = job.staging_dir
        try:
            await job.acquire_slot()
            started = time.monotonic()
            with self.assertRaises(ScanTimeout):
                await job.execute(FakeRequest())
            elapsed = time.monotonic() - started
            self.assertGreaterEqual(elapsed, 0.5 - 0.05)
            self.assertLess(elapsed, 3.0)
        finally:
            await job.close()

        # Slot returned and staging removed even on the timeout path.
        self.assertEqual(supervisor.pool.snapshot()["available"],
                         supervisor.pool.capacity)
        self.assertFalse(staging.exists())

    async def test_worker_is_reaped_after_timeout(self) -> None:
        supervisor = make_supervisor(self._tmp, timeout=0.4, delay=1.0)
        job = supervisor.create_job(source="built-in-demo")
        pid = None
        try:
            await job.acquire_slot()
            with self.assertRaises(ScanTimeout):
                await job.execute(FakeRequest())
            pid = job._process.pid
        finally:
            await job.close()
        # close() waits for full reaping; the PID must no longer exist.
        for _ in range(50):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            except PermissionError:
                # Process exists but signal delivery is sandbox-filtered;
                # asyncio has nonetheless reaped it via waitpid().
                break
            await asyncio.sleep(0.1)
        self.assertIsNotNone(job._process.returncode)


class CancellationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp(prefix="scan-test-")

    async def test_client_disconnect_terminates_worker(self) -> None:
        # Short worker lifespan keeps this deterministic even when the host
        # sandbox filters kill(2); production delivers SIGTERM/SIGKILL itself.
        supervisor = make_supervisor(self._tmp, timeout=10.0, delay=1.0)
        job = supervisor.create_job(source="built-in-demo")
        request = FakeRequest()
        pid = None
        try:
            await job.acquire_slot()
            runner = asyncio.create_task(job.execute(request))
            await asyncio.sleep(0.4)
            pid = job._process.pid
            self.assertIsNone(job._process.returncode)

            request.disconnect()
            with self.assertRaises(ScanCancelled):
                await runner
        finally:
            await job.close()

        # Fully reaped and all per-request resources released.
        self.assertIsNotNone(job._process.returncode)
        self.assertFalse(job.staging_dir.exists())
        self.assertEqual(supervisor.pool.snapshot()["available"],
                         supervisor.pool.capacity)
        for _ in range(50):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            except PermissionError:
                break
            await asyncio.sleep(0.1)

    async def test_disconnect_during_upload_spool_aborts(self) -> None:
        supervisor = make_supervisor(self._tmp)
        job = supervisor.create_job(source="upload")
        request = FakeRequest()
        upload = FakeUpload(b"x" * (8 * 1024 * 1024), stall_after=512 * 1024)
        try:
            task = asyncio.create_task(job.stage_upload(request, upload))
            await asyncio.sleep(0.1)
            request.disconnect()
            with self.assertRaises(ScanCancelled):
                await task
        finally:
            await job.close()
        self.assertFalse(job.staging_dir.exists())
        self.assertEqual(supervisor.pool.snapshot()["in_use"], 0)


class IsolationAndFailureTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp(prefix="scan-test-")
        self.supervisor = make_supervisor(self._tmp)

    async def test_each_job_gets_a_separate_staging_directory(self) -> None:
        first = self.supervisor.create_job(source="built-in-demo")
        second = self.supervisor.create_job(source="built-in-demo")
        try:
            self.assertNotEqual(first.staging_dir, second.staging_dir)
            self.assertTrue(first.staging_dir.is_dir())
            self.assertTrue(second.staging_dir.is_dir())
        finally:
            await first.close()
            await second.close()
        self.assertFalse(first.staging_dir.exists())
        self.assertFalse(second.staging_dir.exists())

    async def test_invalid_archive_returns_structured_400_and_cleans_up(self) -> None:
        job = self.supervisor.create_job(source="upload")
        staging = job.staging_dir
        try:
            await job.stage_upload(FakeRequest(), FakeUpload(b"this is not a tar at all"))
            await job.acquire_slot()
            with self.assertRaises(ScanJobFailed) as caught:
                await job.execute(FakeRequest())
            self.assertEqual(caught.exception.status_code, 400)
            self.assertEqual(caught.exception.detail["code"], "archive_invalid")
        finally:
            await job.close()
        self.assertFalse(staging.exists())
        self.assertEqual(self.supervisor.pool.snapshot()["available"], 2)

    async def test_close_is_idempotent(self) -> None:
        job = self.supervisor.create_job(source="built-in-demo")
        await job.acquire_slot()
        await job.execute(FakeRequest())
        await job.close()
        await job.close()  # must not raise or release the slot twice
        self.assertEqual(self.supervisor.pool.snapshot()["in_use"], 0)


if __name__ == "__main__":
    unittest.main()
