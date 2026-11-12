# 镜像 SUID / SGID 审计

发布镜像前，用一个只读的 Docker 层合并视图找出最终仍带 **SUID** 或 **SGID** 位的普通文件，并定位最后一次写入该文件的镜像层。

页面使用 FastAPI，上传 `docker save` 导出的**单镜像 tar**，按 `manifest.json` 中 `Layers` 的顺序合并元数据。内置四层示例可直接扫描或下载。

## 进程隔离与资源管控（v2）

扫描不再在 Web 进程内用线程执行，而是由**可终止的独立子进程**完成，避免恶意深路径归档在请求取消后持续占用算力：

- 容器内**只有一个 Web 进程**（uvicorn `--workers 1`）。每次扫描（上传与内置示例共用名额）都在一次性 worker 子进程中运行，worker 以独立进程组（`start_new_session`）启动。
- 全局**两个计算名额**，由 Web 进程内的信号量统一管理。名额满时新请求**立即返回 `503`，不排队**。
- 取得名额后 **3 秒**（`SCAN_TIMEOUT_SECONDS`）内未完成，向整个 worker 进程组发 `SIGTERM`，2 秒宽限后升级 `SIGKILL`，并返回 `504`。
- 网页提供**取消按钮**（`AbortController`）；取消、关闭页面或 TCP 断连都会被服务端的断连轮询发现，并按与超时相同的方式终止对应 worker。
- 无论成功、异常、超时还是取消，**只有在 worker 已被回收、管道已关闭、本次上传的独立暂存目录已删除之后才归还名额**；不会只取消等待协程，也不会误清其他请求的暂存（每请求一个全新空目录）。
- 失败（含 503/504/取消/扫描错误）**不返回部分清单**；前端清除旧结果并允许立即再次扫描。
- 计算期间首页 `/`、`/healthz`、示例归档下载 `/api/demo/archive` 不占用名额，始终可响应。
- worker 以 `python -I` 启动、环境变量白名单化，并内置父进程死亡看门狗；即使底层沙箱过滤了 `kill(2)`，Web 进程退出后 worker 也会自行终止，不产生孤儿进程。

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

Compose 以非 root 用户运行，容器根文件系统只读，丢弃全部 capabilities，并启用 `no-new-privileges`。上传字节先暂存在容器内 `/tmp` tmpfs 的**每请求独立目录**中，仅供 worker 只读扫描；归档和层**内容不会被解包**到宿主或容器文件系统，请求结束即删除暂存目录。

### 可调环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `SCAN_MAX_SLOTS` | `2` | 上传扫描与示例扫描共享的并发计算名额 |
| `SCAN_TIMEOUT_SECONDS` | `3.0` | 取得名额后的扫描超时，超时即终止 worker 并返回 504 |
| `SCAN_TMP_DIR` | `/tmp` | 每请求暂存目录的根目录（compose 中为 tmpfs） |
| `SCAN_WORKER_DELAY_SECONDS` | `0` | 仅作用于示例扫描的诊断延迟，用于演示 503/504，生产保持 0 |
| `UPLOAD_TMP_SIZE` | `512m` | `/tmp` tmpfs 大小 |

## 页面功能

- 拖拽或选择 `docker save` 单镜像 tar。
- 一键扫描内置四层示例；扫描中显示**取消扫描**按钮。
- 列出最终 SUID/SGID 普通文件的路径、八进制权限、UID/GID、最后写入层。
- 显示层顺序、manifest 索引和 layer digest。
- 失败时清除旧结果并展示明确错误：名额已满（503）、超时（504）、已取消、hardlink 不支持、越界路径、符号链接层引用、多个镜像、无效 manifest 等。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/` | 网页（含取消按钮） |
| `POST` | `/api/scan` | 上传 tar，表单字段 `archive`（兼容 `image` / `file`），独立子进程执行 |
| `POST` | `/scan` | `/api/scan` 的兼容别名，同一套名额与超时管控 |
| `GET` / `POST` | `/api/demo` | 扫描内置示例，与上传共用两个计算名额 |
| `GET` | `/api/demo/archive` | 下载内置示例 tar（不占名额） |
| `GET` | `/api/openapi.json` | OpenAPI 描述 |
| `GET` | `/healthz` | 健康检查，附带当前名额快照 |

扫描类接口的状态码：

| 状态码 | 含义 |
| --- | --- |
| `200` | 扫描成功，返回完整结果（失败绝不返回部分清单） |
| `400` | 归档/合并错误（如无效 tar、hardlink、越界路径、多镜像） |
| `503` | 两个计算名额均被占用，立即拒绝、不排队（含 `Retry-After: 1`） |
| `504` | 取得名额后超过 3 秒未完成，worker 进程组已被终止 |

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

- 扫描在独立 worker 子进程中进行，与 Web 进程隔离；取消或超时通过进程组信号终止，不依赖 Python 线程的协作式中断。
- worker 以 `python -I` 运行（忽略 `PYTHONPATH`、用户 site-packages），仅接收白名单环境变量，并在父进程死亡时自行退出。
- 每个请求使用全新的独立暂存目录，结束后整体删除；清理只作用于本请求，不会误删其他请求数据。
- 只调用 `tarfile` 读取外层归档与内层层 tar 的头/成员流。
- 没有 `extract()`、`extractall()`，也不会写入任何解包后的文件；暂存的只是上传归档本身的字节。
- 层 tar 通过流式 `r|*` 读取，支持未压缩、gzip、xz、bz2 层。
- 所有成员路径在合并前校验；符号链接层引用会被拒绝。
- 不解析符号链接、不跟随硬链接。
- 服务容器只读、非 root、`cap_drop: ALL`、`no-new-privileges`，单 Web 进程。
- UI 使用 `textContent` 渲染扫描结果，避免镜像内恶意路径造成 XSS；并设置 CSP。

> 上传字节先由应用流式写入 `/tmp`（compose 中为 tmpfs）下每请求独立目录中的单个 `archive.tar`，仅供 worker 只读打开；这不是归档解包，请求结束即删除。若扫描较大的真实镜像，可通过 `UPLOAD_TMP_SIZE` 调整 tmpfs 大小。

## 本地开发与测试

无需 Docker 的测试（合并逻辑 + 子进程生命周期 + 真实 HTTP 集成）：

```bash
python3 -m unittest discover -s tests -v
```

- `tests/test_merger.py`：层合并 / whiteout / 安全边界（18 项）。
- `tests/test_supervisor.py`：真实 worker 子进程的名额、超时、取消、暂存清理与隔离（11 项）。
- `tests/test_http_integration.py`：在后台线程启动真实单进程 uvicorn，覆盖 200/400/503/504、断连、计算期间首页与下载可用性（12 项）。

运行 Web 服务：

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

单独运行一次 worker（调试用）：

```bash
python3 -I app/worker.py --source built-in-demo
```

重新生成内置示例：

```bash
python3 app/sample.py examples/multilayer-demo.tar
```

## 目录结构

```text
app/
  main.py        FastAPI 路由、名额/超时/断连的 HTTP 编排
  supervisor.py  名额池、worker 子进程生命周期、暂存与清理
  worker.py      独立可终止子进程入口，调用 merger 并输出单条 JSON
  merger.py      只读 tar 解析、层合并、SUID/SGID 收集（规则未改动）
  sample.py      内存中生成四层 docker-save 示例
  static/        网页、样式和前端逻辑（含取消按钮）
examples/        内置示例 tar 与说明
tests/           合并规则、子进程生命周期与 HTTP 集成测试
Dockerfile
docker-compose.yml
```

## 已知边界

- 仅支持单镜像 `docker save` 格式；多镜像归档会明确拒绝。
- 硬链接不受支持（按需求明确报错），因此含 hardlink 的镜像不会给出部分结果。
- 不解析镜像 config 中的 `User`、capabilities 或 seccomp 配置；本工具审计的是文件权限位。
- 不把文件名解析到容器用户数据库，故 UID/GID 以数字展示。
