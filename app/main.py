"""FastAPI entry point.

Scans never run inside the web process anymore.  Each scan (upload or the
built-in demo) is executed by a killable worker subprocess managed by
:class:`app.supervisor.ScanSupervisor`.  Only one uvicorn process is started
(see the Dockerfile / compose file), so the in-process slot pool is the single
source of truth for compute capacity:

* two shared compute slots, full capacity => immediate ``503`` (no queue);
* three seconds after a slot is granted without a result => ``504`` and the
  worker is killed;
* client disconnect (cancel button, closed tab, dropped connection) kills the
  worker the same way;
* slots are returned only after the worker is reaped, its pipes are closed and
  the request's private staging directory is removed.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from app.sample import build_demo_archive
from app.supervisor import (
    ScanCancelled,
    ScanJobFailed,
    ScanSupervisor,
    ScanTimeout,
)

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="镜像 SUID / SGID 审计",
    description="只读解析 docker save 单镜像 tar，按层合并 whiteout 后定位高权限普通文件。",
    version="2.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url="/api/openapi.json",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Single supervisor for the single web process: two slots shared by upload
# scans and built-in demo scans.
supervisor = ScanSupervisor()


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    return response


def _capacity_error() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail={
            "code": "capacity_full",
            "message": "计算名额已满（仅 2 个并发扫描），请稍后重试；请求不会排队。",
        },
        headers={"Retry-After": "1"},
    )


def _timeout_error() -> HTTPException:
    return HTTPException(
        status_code=504,
        detail={
            "code": "scan_timeout",
            "message": (
                f"扫描超过 {supervisor.config.timeout_seconds:g} 秒未完成，"
                "计算进程已被终止。"
            ),
        },
    )


async def _run_job(request: Request, job) -> dict:
    """Execute an acquired job and translate lifecycle failures to HTTP."""

    try:
        return await job.execute(request)
    except ScanTimeout:
        raise _timeout_error() from None
    except ScanCancelled:
        # The HTTP peer is gone: there is nobody to send a response to.  Let
        # the ASGI server handle the cancellation; the job's ``finally``
        # teardown has already reaped the worker and cleaned staging.
        raise asyncio.CancelledError from None
    except ScanJobFailed as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict:
    # Deliberately cheap: health checks stay responsive while scans run.
    return {"status": "ok", "slots": supervisor.pool.snapshot()}


@app.post("/api/scan", summary="扫描上传的 docker save 单镜像 tar（独立子进程执行）")
@app.post("/scan", include_in_schema=False)
async def scan_archive(
    request: Request,
    archive: UploadFile | None = File(default=None),
    image: UploadFile | None = File(default=None),
    file: UploadFile | None = File(default=None),
) -> dict:
    upload = archive or image or file
    if upload is None:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "file_missing",
                "message": "请上传 docker save 导出的单镜像 tar 文件（表单字段 archive、image 或 file）",
            },
        )

    job = supervisor.create_job(source="upload")
    try:
        try:
            await job.stage_upload(request, upload)
        except ScanCancelled:
            raise asyncio.CancelledError from None

        if not await job.acquire_slot():
            raise _capacity_error()
        return await _run_job(request, job)
    finally:
        await job.close()
        await upload.close()


@app.get("/api/demo", summary="扫描内置多层示例（与上传共用计算名额）")
@app.post("/api/demo", include_in_schema=False)
async def demo_scan(request: Request) -> dict:
    job = supervisor.create_job(source="built-in-demo")
    try:
        if not await job.acquire_slot():
            raise _capacity_error()
        return await _run_job(request, job)
    finally:
        await job.close()


@app.get("/api/demo/archive", summary="下载内置多层示例 tar")
async def demo_archive() -> Response:
    # No compute slot is needed: serving the cached demo bytes must remain
    # available even while both scan slots are occupied.
    payload = await run_in_threadpool(build_demo_archive)
    return Response(
        content=payload,
        media_type="application/x-tar",
        headers={
            "Content-Disposition": 'attachment; filename="privilege-audit-demo.tar"',
            "Content-Length": str(len(payload)),
        },
    )
