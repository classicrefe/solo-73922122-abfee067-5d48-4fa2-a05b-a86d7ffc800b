"""Read-only merging of docker-save layer metadata.

The scanner never extracts an archive or a layer to the host filesystem.  It
reads tar headers straight from the uploaded archive and keeps an in-memory
virtual filesystem, applying overlayfs whiteout rules as it goes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import tarfile
from typing import BinaryIO, Iterable, Iterator

SUID_BIT = 0o4000
SGID_BIT = 0o2000
SPECIAL_BITS = SUID_BIT | SGID_BIT
OPAQUE_WHITEOUT = ".wh..wh..opq"
WHITEOUT_PREFIX = ".wh."


def _display_text(value: str) -> str:
    """Make a possibly non-UTF-8 tar name safe for JSON/UI output."""

    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return value.encode("utf-8", "surrogateescape").decode(
            "utf-8", "backslashreplace"
        )
    return value


class ScanError(Exception):
    """A user-facing archive/merge error."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str | None = None,
        layer_number: int | None = None,
        layer_path: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.path = path
        self.layer_number = layer_number
        self.layer_path = layer_path

    def to_detail(self) -> dict:
        detail: dict = {
            "code": self.code,
            "message": _display_text(self.message),
        }
        if self.path is not None:
            detail["path"] = _display_text(self.path)
        if self.layer_number is not None:
            detail["layer_number"] = self.layer_number
        if self.layer_path is not None:
            detail["layer_path"] = _display_text(self.layer_path)
        return detail


@dataclass(frozen=True)
class LayerInfo:
    number: int  # 1-based, convenient for people
    manifest_index: int  # 0-based order from manifest.json Layers
    path: str
    name: str

    def as_dict(self) -> dict:
        return {
            "number": self.number,
            "manifest_index": self.manifest_index,
            "path": self.path,
            "name": self.name,
        }


@dataclass(frozen=True)
class FileRecord:
    """One entry in one layer, before overlay merging."""

    path: str  # normalized, no leading slash
    kind: str
    mode: int
    uid: int
    gid: int


@dataclass
class FsEntry:
    record: FileRecord
    layer: LayerInfo


@dataclass
class _Node:
    entry: FsEntry | None = None
    children: dict[str, "_Node"] = field(default_factory=dict)


@dataclass
class ScanResult:
    image: dict
    layers: list[LayerInfo]
    files: list[dict]

    def as_dict(self, *, source: str) -> dict:
        suid_count = sum(1 for item in self.files if "SUID" in item["special_bits"])
        sgid_count = sum(1 for item in self.files if "SGID" in item["special_bits"])
        return {
            "source": source,
            "image": self.image,
            "layers": [layer.as_dict() for layer in self.layers],
            "files": self.files,
            "findings": self.files,  # small compatibility alias
            "summary": {
                "layers_scanned": len(self.layers),
                "privileged_files": len(self.files),
                "suid_files": suid_count,
                "sgid_files": sgid_count,
            },
        }


def normalize_archive_path(raw: str, *, context: str = "archive") -> str:
    """Normalize a tar member name and reject unsafe paths.

    The returned path is relative, has no ``.``/empty components, and never
    contains ``..``.  Absolute paths are rejected instead of being silently
    rooted, so malformed or malicious archives fail loudly.
    """

    if not isinstance(raw, str):
        raise ScanError("invalid_path", f"{context}中的路径不是字符串")
    if "\x00" in raw:
        raise ScanError("unsafe_path", f"{context}中的路径包含 NUL 字节", path=raw)
    if raw.startswith("/"):
        raise ScanError("unsafe_path", f"拒绝绝对路径：{raw}", path=raw)

    parts: list[str] = []
    for part in raw.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise ScanError("unsafe_path", f"拒绝越界路径（..）：{raw}", path=raw)
        parts.append(part)

    return "/".join(parts)


def _path_parts(path: str) -> list[str]:
    return path.split("/") if path else []


def _join_abs(path: str) -> str:
    return "/" + path


def _lookup(root: _Node, path: str, *, create: bool = False) -> _Node | None:
    node = root
    for part in _path_parts(path):
        child = node.children.get(part)
        if child is None:
            if not create:
                return None
            child = _Node()
            node.children[part] = child
        node = child
    return node


def _remove_path(root: _Node, path: str) -> None:
    parts = _path_parts(path)
    if not parts:
        # Removing root is never a valid whiteout operation.
        return
    parent = _lookup(root, "/".join(parts[:-1]))
    if parent is not None:
        parent.children.pop(parts[-1], None)


def _has_non_directory_ancestor(path: str, records: dict[str, FileRecord]) -> bool:
    parts = path.split("/")
    for index in range(1, len(parts)):
        ancestor = records.get("/".join(parts[:index]))
        if ancestor is not None and ancestor.kind != "dir":
            return True
    return False


def _add_record(root: _Node, record: FileRecord, layer: LayerInfo) -> None:
    """Add a current-layer record to the virtual tree.

    A non-directory shadows the whole lower subtree at the same path.  A
    directory entry only updates the directory node, allowing lower children
    to remain unless an opaque marker removed them.  Traversing to a child
    clears a lower non-directory ancestor instead of following any link.
    """

    parts = _path_parts(record.path)
    node = root
    for part in parts[:-1]:
        child = node.children.get(part)
        if child is None:
            child = _Node()
            node.children[part] = child
        elif child.entry is not None and child.entry.record.kind != "dir":
            # A child in this layer implies an implicit directory here.
            child.entry = None
        node = child

    leaf_name = parts[-1]
    leaf = node.children.get(leaf_name)
    if leaf is None:
        leaf = _Node()
        node.children[leaf_name] = leaf

    if record.kind != "dir":
        # Files, symlinks and special files completely replace any lower
        # directory tree at the same path.
        leaf.children.clear()
    leaf.entry = FsEntry(record=record, layer=layer)


def _apply_layer(
    root: _Node,
    records: Iterable[FileRecord],
    whiteouts: Iterable[str],
    opaque_parents: Iterable[str],
    layer: LayerInfo,
) -> None:
    """Apply one layer using two phases.

    Whiteouts are applied against the tree inherited from lower layers first.
    Only then are entries belonging to this layer added.  Consequently, tar
    entry order cannot make a same-layer entry disappear through a whiteout,
    and an opaque marker cannot erase another item from the same layer.
    """

    # Phase 1: remove only lower-layer material.
    for parent in opaque_parents:
        node = _lookup(root, parent)
        if node is not None:
            node.children.clear()
            if node.entry is not None and node.entry.record.kind != "dir":
                node.entry = None

    for target in whiteouts:
        _remove_path(root, target)

    # Phase 2: add this layer's entries.  A later duplicate tar header wins;
    # descendants of a current-layer non-directory cannot coexist with it.
    latest: dict[str, FileRecord] = {}
    for record in records:
        latest[record.path] = record

    effective: dict[str, FileRecord] = {}
    for path, record in latest.items():
        if not _has_non_directory_ancestor(path, latest):
            effective[path] = record

    # Parent-first keeps the tree easy to reason about; the algorithm is
    # nevertheless written to tolerate any current-layer entry order.
    for path, record in sorted(effective.items(), key=lambda item: item[0].count("/")):
        _add_record(root, record, layer)


def _mode_octal(mode: int) -> str:
    return format(mode & 0o7777, "04o")


def _collect_privileged(root: _Node) -> list[dict]:
    results: list[dict] = []

    stack: list[tuple[_Node, list[str]]] = [(root, [])]
    while stack:
        node, parts = stack.pop()
        if node.entry is not None:
            record = node.entry.record
            layer = node.entry.layer
            if record.kind == "file" and (record.mode & SPECIAL_BITS):
                special = []
                if record.mode & SUID_BIT:
                    special.append("SUID")
                if record.mode & SGID_BIT:
                    special.append("SGID")
                relative_path = "/".join(parts)
                display_path = _display_text(relative_path)
                last_layer = layer.as_dict()
                results.append(
                    {
                        "path": _join_abs(display_path),
                        "relative_path": display_path,
                        "mode": record.mode & 0o7777,
                        "mode_octal": _mode_octal(record.mode),
                        "permissions": _mode_octal(record.mode),
                        "uid": record.uid,
                        "gid": record.gid,
                        "special_bits": special,
                        "file_type": "regular",
                        "last_layer": last_layer,
                        "layer_number": layer.number,
                        "layer_manifest_index": layer.manifest_index,
                        "layer_path": layer.path,
                        "layer_name": layer.name,
                    }
                )
        for name, child in node.children.items():
            stack.append((child, parts + [name]))

    results.sort(key=lambda item: item["relative_path"])
    return results


def _layer_name(path: str) -> str:
    parts = path.split("/")
    if len(parts) >= 3 and parts[-3] == "blobs" and parts[-2] == "sha256":
        return "sha256:" + parts[-1]
    if len(parts) >= 2 and parts[0] == "blobs":
        return "/".join(parts[-2:])
    return parts[-1] if parts else path


def _read_json_member(outer: tarfile.TarFile, member: tarfile.TarInfo, *, label: str) -> object:
    extracted = outer.extractfile(member)
    if extracted is None:
        raise ScanError("manifest_unreadable", f"无法读取 {label}")
    try:
        payload = extracted.read()
    except (OSError, tarfile.TarError) as exc:
        raise ScanError("manifest_unreadable", f"读取 {label} 失败：{exc}") from exc
    finally:
        extracted.close()

    try:
        return json.loads(payload.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScanError("manifest_invalid", f"{label} 不是有效的 UTF-8 JSON：{exc}") from exc


def _map_outer_members(outer: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    members: dict[str, tarfile.TarInfo] = {}

    for member in outer.getmembers():
        try:
            path = normalize_archive_path(member.name, context="docker 归档")
        except ScanError as exc:
            raise ScanError(
                exc.code,
                exc.message,
                path=member.name,
            ) from exc
        if not path:
            # A root directory header is harmless metadata.
            if member.isdir():
                continue
            raise ScanError("unsafe_path", "归档根路径不是目录", path=member.name)
        if path in members:
            raise ScanError(
                "duplicate_archive_member",
                f"docker 归档中存在重复路径：{path}",
                path=path,
            )
        members[path] = member

    return members


def _parse_layer(
    outer: tarfile.TarFile,
    member: tarfile.TarInfo,
    layer: LayerInfo,
) -> tuple[list[FileRecord], list[str], list[str]]:
    records: list[FileRecord] = []
    whiteouts: list[str] = []
    opaque_parents: list[str] = []

    extracted = outer.extractfile(member)
    if extracted is None:
        raise ScanError(
            "layer_unreadable",
            f"无法读取镜像层 {layer.path}",
            layer_number=layer.number,
            layer_path=layer.path,
        )

    try:
        # r|* streams the layer and transparently detects gzip/xz/bz2,
        # without writing any unpacked bytes anywhere.
        with tarfile.open(fileobj=extracted, mode="r|*") as layer_tar:
            for tar_info in layer_tar:
                try:
                    path = normalize_archive_path(
                        tar_info.name, context=f"镜像层 {layer.number}"
                    )
                except ScanError as exc:
                    raise ScanError(
                        exc.code,
                        exc.message,
                        path=tar_info.name,
                        layer_number=layer.number,
                        layer_path=layer.path,
                    ) from exc

                if not path:
                    if tar_info.isdir():
                        continue
                    raise ScanError(
                        "unsafe_path",
                        f"镜像层 {layer.number} 的根路径不是目录",
                        path=tar_info.name,
                        layer_number=layer.number,
                        layer_path=layer.path,
                    )

                if tar_info.islnk():
                    raise ScanError(
                        "hardlink_unsupported",
                        f"不支持硬链接（hard link）：{path}（层 {layer.number}）",
                        path=_join_abs(path),
                        layer_number=layer.number,
                        layer_path=layer.path,
                    )

                basename = path.rsplit("/", 1)[-1]
                parent = path.rsplit("/", 1)[0] if "/" in path else ""

                if basename == OPAQUE_WHITEOUT:
                    opaque_parents.append(parent)
                    continue

                if basename.startswith(WHITEOUT_PREFIX):
                    target_name = basename[len(WHITEOUT_PREFIX) :]
                    if target_name in ("", ".", ".."):
                        raise ScanError(
                            "invalid_whiteout",
                            f"无效 whiteout 路径：{path}",
                            path=_join_abs(path),
                            layer_number=layer.number,
                            layer_path=layer.path,
                        )
                    target = f"{parent}/{target_name}" if parent else target_name
                    whiteouts.append(target)
                    continue

                if tar_info.isdir():
                    kind = "dir"
                elif tar_info.issym():
                    kind = "symlink"
                elif tar_info.ischr():
                    kind = "char"
                elif tar_info.isblk():
                    kind = "block"
                elif tar_info.isfifo():
                    kind = "fifo"
                elif tar_info.isreg():
                    kind = "file"
                else:
                    kind = "other"

                records.append(
                    FileRecord(
                        path=path,
                        kind=kind,
                        mode=int(tar_info.mode or 0) & 0o7777,
                        uid=int(tar_info.uid or 0),
                        gid=int(tar_info.gid or 0),
                    )
                )
    except ScanError:
        raise
    except (tarfile.TarError, EOFError, OSError, UnicodeError) as exc:
        raise ScanError(
            "layer_invalid",
            f"镜像层 {layer.path} 不是有效的 tar 数据：{exc}",
            layer_number=layer.number,
            layer_path=layer.path,
        ) from exc
    finally:
        extracted.close()

    return records, whiteouts, opaque_parents


def scan_docker_archive(fileobj: BinaryIO) -> ScanResult:
    """Scan a single-image ``docker save`` tar without extracting anything."""

    try:
        fileobj.seek(0)
    except (AttributeError, OSError) as exc:
        raise ScanError("archive_unreadable", f"无法定位上传文件：{exc}") from exc

    try:
        outer = tarfile.open(fileobj=fileobj, mode="r:*")
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ScanError("archive_invalid", f"上传文件不是有效的 tar 归档：{exc}") from exc

    with outer:
        members = _map_outer_members(outer)

        manifest_member = members.get("manifest.json")
        if manifest_member is None:
            raise ScanError(
                "manifest_missing",
                "未找到 manifest.json；请上传 docker save 导出的单镜像 tar",
            )
        if not manifest_member.isfile():
            raise ScanError(
                "manifest_invalid",
                "manifest.json 不是普通文件；拒绝跟随符号链接或其他特殊文件",
                path="/manifest.json",
            )

        manifest = _read_json_member(outer, manifest_member, label="manifest.json")
        if not isinstance(manifest, list) or not manifest:
            raise ScanError("manifest_invalid", "manifest.json 必须包含至少一个镜像")
        if len(manifest) != 1:
            raise ScanError(
                "multiple_images_unsupported",
                f"归档包含 {len(manifest)} 个镜像；请仅导出单个镜像",
            )
        image = manifest[0]
        if not isinstance(image, dict):
            raise ScanError("manifest_invalid", "manifest.json 的镜像条目格式错误")

        raw_layers = image.get("Layers")
        if not isinstance(raw_layers, list):
            raise ScanError("manifest_invalid", "manifest.json 缺少 Layers 数组")
        if any(not isinstance(item, str) or not item for item in raw_layers):
            raise ScanError("manifest_invalid", "Layers 中存在无效的层路径")

        raw_config = image.get("Config")
        if isinstance(raw_config, str):
            try:
                config_path = normalize_archive_path(
                    raw_config, context="manifest.json Config"
                )
            except ScanError as exc:
                raise ScanError(exc.code, exc.message, path=raw_config) from exc
        else:
            config_path = None

        layers: list[LayerInfo] = []
        root = _Node()

        for manifest_index, raw_layer_path in enumerate(raw_layers):
            try:
                layer_path = normalize_archive_path(
                    raw_layer_path, context="manifest.json Layers"
                )
            except ScanError as exc:
                raise ScanError(
                    exc.code,
                    exc.message,
                    path=raw_layer_path,
                    layer_number=manifest_index + 1,
                ) from exc
            if not layer_path:
                raise ScanError(
                    "manifest_invalid",
                    "Layers 中存在空层路径",
                    layer_number=manifest_index + 1,
                )

            member = members.get(layer_path)
            if member is None:
                raise ScanError(
                    "layer_missing",
                    f"manifest.json 引用的镜像层不存在：{layer_path}",
                    layer_number=manifest_index + 1,
                    layer_path=layer_path,
                )
            if member.islnk():
                raise ScanError(
                    "hardlink_unsupported",
                    f"镜像层 {layer_path} 是硬链接；不支持硬链接",
                    layer_number=manifest_index + 1,
                    layer_path=layer_path,
                )
            if not member.isfile():
                raise ScanError(
                    "layer_not_regular",
                    f"镜像层 {layer_path} 不是普通文件；拒绝跟随符号链接或读取特殊文件",
                    layer_number=manifest_index + 1,
                    layer_path=layer_path,
                )

            layer = LayerInfo(
                number=manifest_index + 1,
                manifest_index=manifest_index,
                path=layer_path,
                name=_layer_name(layer_path),
            )
            records, whiteouts, opaque_parents = _parse_layer(outer, member, layer)
            _apply_layer(root, records, whiteouts, opaque_parents, layer)
            layers.append(layer)

        files = _collect_privileged(root)

        tags = image.get("RepoTags")
        if not isinstance(tags, list):
            tags = []

        image_info = {
            "tags": [str(tag) for tag in tags],
            "config_path": config_path,
        }

        return ScanResult(image=image_info, layers=layers, files=files)


def iter_archive_files(fileobj: BinaryIO) -> Iterator[dict]:
    """Small debugging helper: merge and yield the privileged findings."""

    yield from scan_docker_archive(fileobj).files
