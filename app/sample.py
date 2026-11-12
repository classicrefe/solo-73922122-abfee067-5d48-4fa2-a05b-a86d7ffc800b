"""In-memory, multi-layer docker-save demo used by the web UI.

No demo bytes are unpacked to disk.  The outer archive and every inner layer
are assembled in BytesIO objects and parsed by the same streaming scanner that
handles uploaded archives.
"""

from __future__ import annotations

from functools import lru_cache
import hashlib
import io
import json
import tarfile

DEMO_TAG = "demo/privilege-audit:latest"
_MTIME = 1_700_000_000


def _add_entry(
    tar: tarfile.TarFile,
    name: str,
    *,
    kind: str = "file",
    mode: int = 0o644,
    uid: int = 0,
    gid: int = 0,
    data: bytes = b"",
    linkname: str = "",
    mtime: int = _MTIME,
) -> None:
    info = tarfile.TarInfo(name=name)
    info.mode = mode & 0o7777
    info.uid = uid
    info.gid = gid
    info.mtime = mtime
    if kind == "dir":
        info.type = tarfile.DIRTYPE
        info.size = 0
        tar.addfile(info)
    elif kind == "symlink":
        info.type = tarfile.SYMTYPE
        info.linkname = linkname
        info.size = 0
        tar.addfile(info)
    elif kind == "whiteout":
        info.type = tarfile.REGTYPE
        info.mode = 0
        info.size = 0
        tar.addfile(info)
    else:
        info.type = tarfile.REGTYPE
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))


def _make_tar(entries: list[dict], *, mtime: int) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(
        fileobj=buffer,
        mode="w",
        format=tarfile.PAX_FORMAT,
        encoding="utf-8",
        errors="surrogateescape",
    ) as tar:
        for entry in entries:
            _add_entry(tar, mtime=mtime, **entry)
    return buffer.getvalue()


def _base_layer() -> bytes:
    return _make_tar(
        [
            {"name": "usr", "kind": "dir", "mode": 0o755},
            {"name": "usr/bin", "kind": "dir", "mode": 0o755},
            {"name": "usr/local", "kind": "dir", "mode": 0o755},
            {"name": "usr/local/bin", "kind": "dir", "mode": 0o755},
            {"name": "opt", "kind": "dir", "mode": 0o755},
            {"name": "opt/tools", "kind": "dir", "mode": 0o755},
            {"name": "opt/tools/legacy", "kind": "dir", "mode": 0o755},
            {"name": "var", "kind": "dir", "mode": 0o755},
            {"name": "var/lib", "kind": "dir", "mode": 0o755},
            {"name": "var/lib/cache", "kind": "dir", "mode": 0o755},
            {"name": "etc", "kind": "dir", "mode": 0o755},
            {
                "name": "usr/bin/passwd",
                "mode": 0o4755,
                "uid": 0,
                "gid": 0,
                "data": b"base passwd binary\n",
            },
            {
                "name": "usr/bin/sudo",
                "mode": 0o4755,
                "uid": 0,
                "gid": 0,
                "data": b"base sudo binary\n",
            },
            {
                "name": "usr/bin/wall",
                "mode": 0o2755,
                "uid": 0,
                "gid": 5,
                "data": b"base wall binary\n",
            },
            {
                "name": "opt/tools/legacy/helper",
                "mode": 0o4755,
                "uid": 0,
                "gid": 0,
                "data": b"old helper\n",
            },
            {
                "name": "opt/tools/legacy/stale",
                "mode": 0o2755,
                "uid": 0,
                "gid": 0,
                "data": b"stale helper\n",
            },
            {
                "name": "var/lib/cache/oldbin",
                "mode": 0o4755,
                "uid": 0,
                "gid": 0,
                "data": b"old cache binary\n",
            },
            {
                "name": "usr/local/bin/oldtool",
                "mode": 0o4755,
                "uid": 0,
                "gid": 0,
                "data": b"file that becomes a directory\n",
            },
            {
                "name": "etc/motd",
                "mode": 0o644,
                "uid": 0,
                "gid": 0,
                "data": b"demo image\n",
            },
        ],
        mtime=_MTIME,
    )


def _update_layer() -> bytes:
    return _make_tar(
        [
            {"name": "usr/bin", "kind": "dir", "mode": 0o755},
            # A same-layer replacement is listed before the whiteout on
            # purpose: whiteouts must only remove lower-layer material.
            {
                "name": "usr/bin/passwd",
                "mode": 0o0755,
                "uid": 0,
                "gid": 0,
                "data": b"safe passwd wrapper\n",
            },
            {"name": "usr/bin/.wh.passwd", "kind": "whiteout"},
            {
                "name": "usr/bin/sudo",
                "mode": 0o0755,
                "uid": 0,
                "gid": 0,
                "data": b"sudo without suid\n",
            },
            {
                "name": "usr/bin/ping",
                "mode": 0o4755,
                "uid": 0,
                "gid": 0,
                "data": b"ping with suid\n",
            },
            {
                "name": "usr/bin/newns",
                "mode": 0o0755,
                "uid": 0,
                "gid": 0,
                "data": b"ordinary binary\n",
            },
        ],
        mtime=_MTIME + 1,
    )


def _opaque_and_swap_layer() -> bytes:
    return _make_tar(
        [
            {"name": "opt/tools/legacy", "kind": "dir", "mode": 0o755},
            {
                "name": "opt/tools/legacy/newhelper",
                "mode": 0o2755,
                "uid": 0,
                "gid": 0,
                "data": b"new helper\n",
            },
            # Listed after newhelper to prove the marker only affects lower
            # layers, independent of tar entry order.
            {"name": "opt/tools/legacy/.wh..wh..opq", "kind": "whiteout"},
            {"name": "var/lib", "kind": "dir", "mode": 0o755},
            # Lower layer had var/lib/cache/ as a directory with a SUID child.
            # This regular file replaces the whole subtree.
            {
                "name": "var/lib/cache",
                "mode": 0o2755,
                "uid": 0,
                "gid": 0,
                "data": b"cache is now a file\n",
            },
        ],
        mtime=_MTIME + 2,
    )


def _file_to_directory_layer() -> bytes:
    return _make_tar(
        [
            {"name": "usr/local/bin/oldtool", "kind": "dir", "mode": 0o755},
            {
                "name": "usr/local/bin/oldtool/wrapper",
                "mode": 0o4755,
                "uid": 0,
                "gid": 0,
                "data": b"wrapper with suid\n",
            },
            # A symlink is retained as a symlink and never followed or counted.
            {
                "name": "usr/bin/ping-link",
                "kind": "symlink",
                "mode": 0o777,
                "uid": 0,
                "gid": 0,
                "linkname": "/usr/bin/ping",
            },
        ],
        mtime=_MTIME + 3,
    )


@lru_cache(maxsize=1)
def build_demo_archive() -> bytes:
    """Build a deterministic single-image docker-save tar in memory."""

    layer_payloads = [
        _base_layer(),
        _update_layer(),
        _opaque_and_swap_layer(),
        _file_to_directory_layer(),
    ]
    layer_paths: list[str] = []
    diff_ids: list[str] = []
    for payload in layer_payloads:
        digest = hashlib.sha256(payload).hexdigest()
        diff_ids.append("sha256:" + digest)
        layer_paths.append("blobs/sha256/" + digest)

    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "Cmd": ["/bin/sh"],
        },
        "rootfs": {"type": "layers", "diff_ids": diff_ids},
        "history": [{"created": "2026-01-01T00:00:00Z", "created_by": "demo layer"}]
        * len(layer_payloads),
    }
    config_bytes = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
    config_digest = hashlib.sha256(config_bytes).hexdigest()
    config_path = "blobs/sha256/" + config_digest

    manifest = [
        {
            "Config": config_path,
            "RepoTags": [DEMO_TAG],
            "Layers": layer_paths,
        }
    ]
    manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode()

    buffer = io.BytesIO()
    with tarfile.open(
        fileobj=buffer,
        mode="w",
        format=tarfile.PAX_FORMAT,
        encoding="utf-8",
    ) as outer:
        for directory in ("blobs", "blobs/sha256"):
            info = tarfile.TarInfo(directory)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.uid = 0
            info.gid = 0
            info.mtime = _MTIME
            outer.addfile(info)

        info = tarfile.TarInfo("manifest.json")
        info.mode = 0o644
        info.uid = 0
        info.gid = 0
        info.size = len(manifest_bytes)
        info.mtime = _MTIME
        outer.addfile(info, io.BytesIO(manifest_bytes))

        info = tarfile.TarInfo(config_path)
        info.mode = 0o644
        info.uid = 0
        info.gid = 0
        info.size = len(config_bytes)
        info.mtime = _MTIME
        outer.addfile(info, io.BytesIO(config_bytes))

        for path, payload in zip(layer_paths, layer_payloads):
            info = tarfile.TarInfo(path)
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.size = len(payload)
            info.mtime = _MTIME
            outer.addfile(info, io.BytesIO(payload))

    return buffer.getvalue()


if __name__ == "__main__":
    # Optional convenience: write the demo archive to an explicitly supplied
    # path.  The web app itself never writes archive content to disk.
    import sys

    output = sys.argv[1] if len(sys.argv) > 1 else "-"
    payload = build_demo_archive()
    if output == "-":
        sys.stdout.buffer.write(payload)
    else:
        with open(output, "wb") as handle:
            handle.write(payload)
