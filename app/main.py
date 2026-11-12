from __future__ import annotations

import io
import logging
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from app.merger import ScanError, scan_docker_archive
from app.sample import build_demo_archive

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="镜像 SUID / SGID 审计",
    description="只读解析 docker save 单镜像 tar，按层合并 whiteout 后定位高权限普通文件。",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url="/api/openapi.json",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    return response


def _scan_error(exc: ScanError) -> HTTPException:
    return HTTPException(status_code=400, detail=exc.to_detail())


async def _scan_upload(upload: UploadFile) -> dict:
    try:
        result = await run_in_threadpool(scan_docker_archive, upload.file)
    except ScanError as exc:
        raise _scan_error(exc) from exc
    except Exception as exc:  # defensive: never expose a stack trace to the client
        logger.exception("Unexpected archive scan failure")
        raise HTTPException(
            status_code=500,
            detail={
                "code": "scan_failed",
                "message": f"扫描失败：{type(exc).__name__}",
            },
        ) from exc
    return result.as_dict(source="upload")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict:
    return {"status": "ok"}


@app.post("/api/scan", summary="扫描上传的 docker save 单镜像 tar")
@app.post("/scan", include_in_schema=False)
async def scan_archive(
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
    try:
        return await _scan_upload(upload)
    finally:
        await upload.close()


def _scan_demo() -> dict:
    try:
        result = scan_docker_archive(io.BytesIO(build_demo_archive()))
    except ScanError as exc:
        raise _scan_error(exc) from exc
    return result.as_dict(source="built-in-demo")


@app.get("/api/demo", summary="扫描内置多层示例")
@app.post("/api/demo", include_in_schema=False)
async def demo_scan() -> dict:
    return await run_in_threadpool(_scan_demo)


@app.get("/api/demo/archive", summary="下载内置多层示例 tar")
async def demo_archive() -> Response:
    payload = await run_in_threadpool(build_demo_archive)
    return Response(
        content=payload,
        media_type="application/x-tar",
        headers={
            "Content-Disposition": 'attachment; filename="privilege-audit-demo.tar"',
            "Content-Length": str(len(payload)),
        },
    )
