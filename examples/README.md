# 内置多层示例

`multilayer-demo.tar` 是 `docker save` 格式的单镜像归档，由
`app/sample.py` 在内存中确定性生成（也可重新生成）：

```bash
python3 app/sample.py examples/multilayer-demo.tar
```

它包含 4 个层，覆盖以下合并规则：

| 层 | 示例内容 |
| --- | --- |
| L1 | `usr/bin/passwd`、`usr/bin/sudo` 为 SUID；`usr/bin/wall` 为 SGID |
| L2 | whiteout 删除低层 `passwd`，同层新增安全版 `passwd`；`sudo` 改为 0755；新增 SUID `ping` |
| L3 | `opt/tools/legacy/` 使用 opaque whiteout；`var/lib/cache/` 从目录被换成 SGID 普通文件 |
| L4 | `usr/local/bin/oldtool` 从普通文件被换成目录，子项 `wrapper` 为 SUID；符号链接不被跟随 |

最终应报告 5 个文件：2 个 SUID、3 个 SGID。
