# 镜像 SUID / SGID 审计

发布镜像前，用一个只读的 Docker 层合并视图找出最终仍带 **SUID** 或 **SGID** 位的普通文件，并定位最后一次写入该文件的镜像层。

页面使用 FastAPI，上传 `docker save` 导出的**单镜像 tar**，按 `manifest.json` 中 `Layers` 的顺序合并元数据。内置四层示例可直接扫描或下载。

## 快速启动

```bash
docker compose up --build
```

打开 <http://localhost:8000>。若 8000 端口被占用：

```bash
APP_PORT=8080 docker compose up --build
```

停止：

```bash
docker compose down
```

Compose 以非 root 用户运行，容器根文件系统只读，丢弃全部 capabilities，并启用 `no-new-privileges`。上传暂存在容器内 `/tmp` tmpfs 中；归档和层**内容不会被解包**到宿主或容器文件系统。

## 页面功能

- 拖拽或选择 `docker save` 单镜像 tar。
- 一键扫描内置四层示例。
- 列出最终 SUID/SGID 普通文件的路径、八进制权限、UID/GID、最后写入层。
- 显示层顺序、manifest 索引和 layer digest。
- 错误会明确区分：hardlink 不支持、越界路径、符号链接层引用、多个镜像、无效 manifest 等。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/` | 网页 |
| `POST` | `/api/scan` | 上传 tar，表单字段 `archive`（兼容 `image` / `file`） |
| `GET` | `/api/demo` | 扫描内置示例，返回与上传相同结构 |
| `GET` | `/api/demo/archive` | 下载内置示例 tar |
| `GET` | `/api/openapi.json` | OpenAPI 描述 |
| `GET` | `/healthz` | 健康检查 |

示例：

```bash
curl -sS -F archive=@examples/multilayer-demo.tar \
  http://localhost:8000/api/scan | jq
```

响应节选：

```json
{
  "source": "upload",
  "image": {"tags": ["demo/privilege-audit:latest"], "config_path": "blobs/sha256/..."},
  "layers": [
    {"number": 1, "manifest_index": 0, "path": "blobs/sha256/...", "name": "sha256:..."}
  ],
  "files": [
    {
      "path": "/usr/bin/ping",
      "relative_path": "usr/bin/ping",
      "mode": 2541,
      "mode_octal": "4755",
      "permissions": "4755",
      "uid": 0,
      "gid": 0,
      "special_bits": ["SUID"],
      "file_type": "regular",
      "last_layer": {
        "number": 2,
        "manifest_index": 1,
        "path": "blobs/sha256/...",
        "name": "sha256:..."
      },
      "layer_number": 2,
      "layer_manifest_index": 1
    }
  ],
  "summary": {
    "layers_scanned": 4,
    "privileged_files": 5,
    "suid_files": 2,
    "sgid_files": 3
  }
}
```

- `number` 是便于阅读的 1-based 层号。
- `manifest_index` 是 `manifest.json` 中 `Layers` 数组的 0-based 下标。
- `mode` 是权限位整数，`mode_octal` 是补足四位的八进制字符串（如 `4755`）。

错误响应采用 FastAPI 的 `detail` 对象：

```json
{
  "detail": {
    "code": "hardlink_unsupported",
    "message": "不支持硬链接（hard link）：/hard（层 2）",
    "path": "/hard",
    "layer_number": 2,
    "layer_path": "blobs/sha256/..."
  }
}
```

## 合并规则

1. **严格按 manifest 顺序**逐层应用，先应用较低层，再应用较高层。
2. **普通 whiteout**（如 `dir/.wh.file`）只从已继承的低层视图中删除 `dir/file` 及其子树。
3. **opaque whiteout**（`dir/.wh..wh..opq`）只清空低层目录 `dir/` 的内容，目录节点和本层新增内容保留。
4. **whiteout 与同层新增分离处理**：先对低层应用全部 whiteout，再添加本层条目。因此无论 `.wh.*` 在 tar 中排在本层新文件之前还是之后，结果一致。
5. **目录/文件互换**：
   - 上层普通文件、符号链接或特殊文件替换低层目录时，低层整棵子树被遮蔽。
   - 上层目录替换低层普通文件时，低层文件消失，子项按新层建立。
6. **符号链接不跟随**：只记录符号链接本身，不解析 `linkname`，更不会把目标文件或链接目标算作普通文件。
7. **硬链接明确拒绝**：层内出现 hardlink 立即返回 `hardlink_unsupported`，而不是猜测目标元数据。
8. **越界路径拒绝**：绝对路径、包含 `..` 的路径、NUL 字节路径都会失败，不会静默改写路径。

最终仅列出满足以下条件的条目：

- 类型为普通文件（`regular file`）；
- 权限位包含 `0o4000`（SUID）或 `0o2000`（SGID）；
- 未被更高层删除、遮蔽或替换。

## 安全设计

- 只调用 `tarfile` 读取外层归档与内层层 tar 的头/成员流。
- 没有 `extract()`、`extractall()`，也不会写入任何解包后的文件。
- 层 tar 通过流式 `r|*` 读取，支持未压缩、gzip、xz、bz2 层。
- 所有成员路径在合并前校验；符号链接层引用会被拒绝。
- 不解析符号链接、不跟随硬链接。
- 服务容器只读、非 root、`cap_drop: ALL`。
- UI 使用 `textContent` 渲染扫描结果，避免镜像内恶意路径造成 XSS；并设置 CSP。

> 上传文件本身由 ASGI/Starlette 暂存（默认超过 1 MiB 会落到 `/tmp`）。Compose 把 `/tmp` 挂为 tmpfs；这只是上传字节的暂存，不是归档解包。若扫描较大的真实镜像，可通过 `UPLOAD_TMP_SIZE` 调整 tmpfs 大小。

## 本地开发与测试

无需 Docker 的合并逻辑测试：

```bash
python3 -m unittest discover -s tests -v
```

运行 Web 服务：

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

重新生成内置示例：

```bash
python3 app/sample.py examples/multilayer-demo.tar
```

## 目录结构

```text
app/
  main.py        FastAPI 路由、上传与错误响应
  merger.py      只读 tar 解析、层合并、SUID/SGID 收集
  sample.py      内存中生成四层 docker-save 示例
  static/        网页、样式和前端逻辑
examples/        内置示例 tar 与说明
tests/           合并规则与安全边界测试
Dockerfile
docker-compose.yml
```

## 已知边界

- 仅支持单镜像 `docker save` 格式；多镜像归档会明确拒绝。
- 硬链接不受支持（按需求明确报错），因此含 hardlink 的镜像不会给出部分结果。
- 不解析镜像 config 中的 `User`、capabilities 或 seccomp 配置；本工具审计的是文件权限位。
- 不把文件名解析到容器用户数据库，故 UID/GID 以数字展示。
