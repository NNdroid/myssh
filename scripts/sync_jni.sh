#!/usr/bin/env bash
# ============================================================
# sync_jni.sh — 将工作目录 myssh 的核心 Go 源码同步到安卓构建用的
#               E:/AndroidStudioProjects/Stun/core/jni/myssh 拷贝。
#
# 用法（Git Bash）：  bash scripts/sync_jni.sh
# 可选：             bash scripts/sync_jni.sh --with-mod   # 同时覆盖 go.mod/go.sum
#
# 说明：
#   - 仅同步「根目录」的 *.go（含 *_test.go），不碰 web/ cmd/ bin/ scripts/ 子包。
#   - 采用镜像策略：源里没有的 jni 根 .go 会被删除，避免旧文件残留导致重复定义。
#   - 默认不覆盖 go.mod/go.sum；若依赖有变动，请确认 jni 的 go.mod 是否需要手动同步，
#     或用 --with-mod 强制覆盖（仅在两份 go.mod 结构一致时安全）。
# ============================================================
set -euo pipefail

SRC="E:/SourceTreeProjects/myssh"
DST="E:/AndroidStudioProjects/Stun/core/jni/myssh"
WITH_MOD=0

for arg in "$@"; do
  case "$arg" in
    --with-mod) WITH_MOD=1 ;;
    *) echo "未知参数: $arg" >&2; exit 1 ;;
  esac
done

if [ ! -d "$SRC" ]; then echo "源目录不存在: $SRC" >&2; exit 1; fi
if [ ! -d "$DST" ]; then echo "目标目录不存在: $DST" >&2; exit 1; fi

echo "==> 同步 $SRC -> $DST"

# 1) 删除 jni 中多余的根 .go（源里已不存在的）
shopt -s nullglob
for j in "$DST"/*.go; do
  b="$(basename "$j")"
  if [ ! -f "$SRC/$b" ]; then
    echo "  删除陈旧文件: $b"
    rm -f "$j"
  fi
done

# 2) 复制/覆盖所有根 .go
for f in "$SRC"/*.go; do
  b="$(basename "$f")"
  cp -f "$f" "$DST/$b"
done
shopt -u nullglob

# 3) go.mod / go.sum 差异提示
for m in go.mod go.sum; do
  if [ -f "$SRC/$m" ] && [ -f "$DST/$m" ]; then
    if ! diff -q "$SRC/$m" "$DST/$m" >/dev/null; then
      if [ "$WITH_MOD" -eq 1 ]; then
        echo "  覆盖 $m"
        cp -f "$SRC/$m" "$DST/$m"
      else
        echo "  [提示] $m 与工作目录不同，依赖若有变动请手动同步或加 --with-mod"
      fi
    fi
  fi
done

echo "==> 完成。请在 Android Studio 中重新构建 aar（Build -> Make Module 'core'）。"
