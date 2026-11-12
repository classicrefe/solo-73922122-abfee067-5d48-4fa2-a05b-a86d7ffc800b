from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import unittest

from app.merger import ScanError, scan_docker_archive
from app.sample import build_demo_archive


def make_layer(entries: list[dict]) -> bytes:
    """Build one layer tar.

    Entry keys: name, kind (file/dir/symlink/hardlink/whiteout), mode, uid,
    gid, data, linkname.  The list order is preserved exactly.
    """

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for entry in entries:
            info = tarfile.TarInfo(entry["name"])
            kind = entry.get("kind", "file")
            info.mode = entry.get("mode", 0o644) & 0o7777
            info.uid = entry.get("uid", 0)
            info.gid = entry.get("gid", 0)
            info.mtime = 1_600_000_000
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                info.size = 0
                tar.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = entry["linkname"]
                info.size = 0
                tar.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = entry["linkname"]
                info.size = 0
                tar.addfile(info)
            elif kind == "whiteout":
                info.type = tarfile.REGTYPE
                info.mode = 0
                info.size = 0
                tar.addfile(info)
            else:
                data = entry.get("data", b"payload")
                info.type = tarfile.REGTYPE
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def make_archive(
    layers: list[bytes],
    *,
    tag: str = "test/image:latest",
    multiple: bool = False,
    unsafe_outer_name: str | None = None,
) -> bytes:
    layer_paths = []
    for index, payload in enumerate(layers):
        layer_paths.append(f"layer-{index}.tar")

    config = {"architecture": "amd64", "os": "linux"}
    config_bytes = json.dumps(config).encode()
    config_digest = hashlib.sha256(config_bytes).hexdigest()
    config_path = f"blobs/sha256/{config_digest}"

    manifest = [{"Config": config_path, "RepoTags": [tag], "Layers": layer_paths}]
    if multiple:
        manifest.append(
            {
                "Config": config_path,
                "RepoTags": ["test/second:latest"],
                "Layers": layer_paths[:1],
            }
        )
    manifest_bytes = json.dumps(manifest).encode()

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as outer:
        if unsafe_outer_name:
            info = tarfile.TarInfo(unsafe_outer_name)
            payload = b"unsafe"
            info.size = len(payload)
            outer.addfile(info, io.BytesIO(payload))

        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest_bytes)
        outer.addfile(info, io.BytesIO(manifest_bytes))

        info = tarfile.TarInfo(config_path)
        info.size = len(config_bytes)
        outer.addfile(info, io.BytesIO(config_bytes))

        for path, payload in zip(layer_paths, layers):
            info = tarfile.TarInfo(path)
            info.size = len(payload)
            outer.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def scan(layers: list[bytes], **kwargs):
    archive = make_archive(layers, **kwargs)
    return scan_docker_archive(io.BytesIO(archive))


class DemoTests(unittest.TestCase):
    def test_builtin_demo_covers_merge_rules(self):
        result = scan_docker_archive(io.BytesIO(build_demo_archive())).as_dict(
            source="demo"
        )
        self.assertEqual(result["summary"]["layers_scanned"], 4)
        self.assertEqual(result["summary"]["privileged_files"], 5)
        self.assertEqual(result["summary"]["suid_files"], 2)
        self.assertEqual(result["summary"]["sgid_files"], 3)
        paths = [item["path"] for item in result["files"]]
        self.assertEqual(
            paths,
            [
                "/opt/tools/legacy/newhelper",
                "/usr/bin/ping",
                "/usr/bin/wall",
                "/usr/local/bin/oldtool/wrapper",
                "/var/lib/cache",
            ],
        )
        by_path = {item["path"]: item for item in result["files"]}
        self.assertEqual(by_path["/usr/bin/wall"]["mode_octal"], "2755")
        self.assertEqual(by_path["/usr/bin/wall"]["gid"], 5)
        self.assertEqual(by_path["/usr/bin/ping"]["mode_octal"], "4755")
        self.assertEqual(by_path["/usr/bin/ping"]["last_layer"]["number"], 2)
        self.assertEqual(by_path["/var/lib/cache"]["last_layer"]["number"], 3)
        self.assertEqual(
            by_path["/usr/local/bin/oldtool/wrapper"]["last_layer"]["number"], 4
        )
        # Whiteout removed lower /usr/bin/passwd, but the same-layer safe
        # replacement exists and is not privileged.  sudo was rewritten 0755.
        self.assertNotIn("/usr/bin/passwd", paths)
        self.assertNotIn("/usr/bin/sudo", paths)
        # Opaque marker hid the two lower helpers.
        self.assertNotIn("/opt/tools/legacy/helper", paths)
        self.assertNotIn("/opt/tools/legacy/stale", paths)
        # File/dir swaps shadowed old entries.
        self.assertNotIn("/var/lib/cache/oldbin", paths)
        self.assertNotIn("/usr/local/bin/oldtool", paths)
        # Symlinks are never followed or listed.
        self.assertNotIn("/usr/bin/ping-link", paths)


class WhiteoutTests(unittest.TestCase):
    def test_whiteout_only_removes_lower_even_when_marker_comes_last(self):
        base = make_layer(
            [{"name": "a", "mode": 0o0755, "data": b"lower"}]
        )
        update = make_layer(
            [
                {"name": "a", "mode": 0o4755, "data": b"same layer first"},
                {"name": ".wh.a", "kind": "whiteout"},
            ]
        )
        result = scan([base, update])
        self.assertEqual(len(result.files), 1)
        item = result.files[0]
        self.assertEqual(item["path"], "/a")
        self.assertEqual(item["mode_octal"], "4755")
        self.assertEqual(item["last_layer"]["number"], 2)

    def test_whiteout_only_removes_lower_even_when_marker_comes_first(self):
        base = make_layer(
            [{"name": "a", "mode": 0o0755, "data": b"lower"}]
        )
        update = make_layer(
            [
                {"name": ".wh.a", "kind": "whiteout"},
                {"name": "a", "mode": 0o4755, "data": b"same layer second"},
            ]
        )
        result = scan([base, update])
        self.assertEqual(len(result.files), 1)
        self.assertEqual(result.files[0]["path"], "/a")
        self.assertEqual(result.files[0]["last_layer"]["number"], 2)

    def test_whiteout_removes_a_directory_subtree(self):
        base = make_layer(
            [
                {"name": "d", "kind": "dir", "mode": 0o755},
                {"name": "d/old", "mode": 0o4755},
            ]
        )
        update = make_layer([{"name": ".wh.d", "kind": "whiteout"}])
        self.assertEqual(scan([base, update]).files, [])

    def test_opaque_whiteout_keeps_same_layer_items_any_order(self):
        base = make_layer(
            [
                {"name": "d", "kind": "dir", "mode": 0o755},
                {"name": "d/old", "mode": 0o4755},
            ]
        )
        update = make_layer(
            [
                {"name": "d/new", "mode": 0o4755, "data": b"new"},
                {"name": "d/.wh..wh..opq", "kind": "whiteout"},
            ]
        )
        result = scan([base, update])
        self.assertEqual([item["path"] for item in result.files], ["/d/new"])
        self.assertEqual(result.files[0]["last_layer"]["number"], 2)

    def test_opaque_root_keeps_same_layer_items(self):
        base = make_layer([{"name": "old", "mode": 0o4755}])
        update = make_layer(
            [
                {"name": ".wh..wh..opq", "kind": "whiteout"},
                {"name": "new", "mode": 0o4755},
            ]
        )
        result = scan([base, update])
        self.assertEqual([item["path"] for item in result.files], ["/new"])


class SwapAndLinkTests(unittest.TestCase):
    def test_lower_directory_replaced_by_regular_file(self):
        base = make_layer(
            [
                {"name": "d", "kind": "dir", "mode": 0o755},
                {"name": "d/child", "mode": 0o4755},
            ]
        )
        update = make_layer([{"name": "d", "mode": 0o2755, "data": b"now a file"}])
        result = scan([base, update])
        self.assertEqual([item["path"] for item in result.files], ["/d"])
        self.assertEqual(result.files[0]["mode_octal"], "2755")
        self.assertEqual(result.files[0]["last_layer"]["number"], 2)

    def test_lower_file_replaced_by_directory_with_child(self):
        base = make_layer([{"name": "d", "mode": 0o4755, "data": b"old file"}])
        update = make_layer(
            [
                {"name": "d", "kind": "dir", "mode": 0o755},
                {"name": "d/child", "mode": 0o4755},
            ]
        )
        result = scan([base, update])
        self.assertEqual([item["path"] for item in result.files], ["/d/child"])
        self.assertEqual(result.files[0]["last_layer"]["number"], 2)

    def test_symlink_is_not_followed_or_listed(self):
        base = make_layer([{"name": "target", "mode": 0o4755}])
        update = make_layer(
            [
                {
                    "name": "link",
                    "kind": "symlink",
                    "mode": 0o4755,
                    "linkname": "/target",
                }
            ]
        )
        result = scan([base, update])
        self.assertEqual([item["path"] for item in result.files], ["/target"])

    def test_symlink_replacing_directory_hides_lower_children(self):
        base = make_layer(
            [
                {"name": "d", "kind": "dir", "mode": 0o755},
                {"name": "d/child", "mode": 0o4755},
            ]
        )
        update = make_layer(
            [
                {
                    "name": "d",
                    "kind": "symlink",
                    "mode": 0o777,
                    "linkname": "/etc",
                }
            ]
        )
        self.assertEqual(scan([base, update]).files, [])

    def test_hardlink_is_rejected_explicitly(self):
        base = make_layer([{"name": "real", "mode": 0o4755}])
        update = make_layer(
            [{"name": "hard", "kind": "hardlink", "linkname": "real"}]
        )
        with self.assertRaises(ScanError) as caught:
            scan([base, update])
        self.assertEqual(caught.exception.code, "hardlink_unsupported")
        self.assertIn("hard link", caught.exception.message)
        self.assertEqual(caught.exception.path, "/hard")

    def test_last_write_layer_is_reported(self):
        base = make_layer([{"name": "tool", "mode": 0o4755}])
        update = make_layer([{"name": "tool", "mode": 0o4755, "data": b"rewrite"}])
        result = scan([base, update])
        self.assertEqual(result.files[0]["last_layer"]["number"], 2)
        self.assertEqual(result.files[0]["last_layer"]["manifest_index"], 1)


class SafetyAndValidationTests(unittest.TestCase):
    def test_parent_traversal_in_layer_is_rejected(self):
        layer = make_layer([{"name": "../escape", "mode": 0o4755}])
        with self.assertRaises(ScanError) as caught:
            scan([layer])
        self.assertEqual(caught.exception.code, "unsafe_path")

    def test_absolute_path_in_layer_is_rejected(self):
        layer = make_layer([{"name": "/etc/evil", "mode": 0o4755}])
        with self.assertRaises(ScanError) as caught:
            scan([layer])
        self.assertEqual(caught.exception.code, "unsafe_path")

    def test_unsafe_unrelated_outer_path_is_rejected(self):
        layer = make_layer([{"name": "ok", "mode": 0o4755}])
        with self.assertRaises(ScanError) as caught:
            scan([layer], unsafe_outer_name="../junk")
        self.assertEqual(caught.exception.code, "unsafe_path")

    def test_multiple_images_are_rejected(self):
        layer = make_layer([{"name": "ok", "mode": 0o4755}])
        with self.assertRaises(ScanError) as caught:
            scan([layer], multiple=True)
        self.assertEqual(caught.exception.code, "multiple_images_unsupported")

    def test_invalid_tar_is_rejected(self):
        with self.assertRaises(ScanError) as caught:
            scan_docker_archive(io.BytesIO(b"not a tar archive"))
        self.assertEqual(caught.exception.code, "archive_invalid")

    def test_gzip_compressed_layer_is_supported(self):
        layer = gzip.compress(make_layer([{"name": "ok", "mode": 0o4755}]))
        result = scan([layer])
        self.assertEqual(result.files[0]["path"], "/ok")


if __name__ == "__main__":
    unittest.main()
