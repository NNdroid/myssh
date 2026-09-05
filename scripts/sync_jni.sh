#!/usr/bin/env bash
# ============================================================
# sync_jni.sh — 将工作目录 myssh 的核心 Go 源码同步到 Android
#               子模块 E:/AndroidStudioProjects/Stun/core/jni/myssh。
#
# 用法（Git Bash）：
#   bash scripts/sync_jni.sh
#   bash scripts/sync_jni.sh --with-mod
#   bash scripts/sync_jni.sh --dry-run --with-mod
#
# 说明：
#   - 不复制 .git；通过 Git 将目标子模块切到源仓库的确切 HEAD。
#   - 镜像同步根目录 *.go（含 *_test.go），删除源里已经不存在的旧文件。
#   - --with-mod 同步 go.mod/go.sum，并把四个 SDK 的本地 replace 路径
#     重写为相对于 Android 子模块的正确路径。
#   - --dry-run 只报告动作，不改文件、不 fetch、不 checkout。
# ============================================================
set -euo pipefail

SRC="E:/SourceTreeProjects/myssh"
DST="E:/AndroidStudioProjects/Stun/core/jni/myssh"
SDK_ROOT="E:/GolandProjects"
WITH_MOD=0
DRY_RUN=0

for arg in "$@"; do
  case "$arg" in
    --with-mod) WITH_MOD=1 ;;
    --dry-run) DRY_RUN=1 ;;
    *) echo "未知参数: $arg" >&2; exit 1 ;;
  esac
done

if [ ! -d "$SRC" ]; then echo "源目录不存在: $SRC" >&2; exit 1; fi
if [ ! -d "$DST" ]; then echo "目标目录不存在: $DST" >&2; exit 1; fi
if ! git -C "$SRC" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "源目录不是 Git 工作区: $SRC" >&2
  exit 1
fi
if ! git -C "$DST" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "目标目录不是 Git 子模块工作区: $DST" >&2
  exit 1
fi

SRC_HEAD="$(git -C "$SRC" rev-parse HEAD)"
DST_HEAD="$(git -C "$DST" rev-parse HEAD)"

echo "==> 同步 $SRC -> $DST"
echo "  源 commit:  $SRC_HEAD"
echo "  目标 commit: $DST_HEAD"

if ! git -C "$SRC" diff --quiet -- ||
   ! git -C "$SRC" diff --cached --quiet -- ||
   [ -n "$(git -C "$SRC" ls-files --others --exclude-standard)" ]; then
  echo "  [警告] 源仓库存在未提交改动；版本号记录的是基准 commit，未提交内容不在 hash 中。"
fi

# 1) 对齐目标子模块的 Git commit。目标不是独立副本，因此绝不能复制 .git。
if [ "$SRC_HEAD" != "$DST_HEAD" ]; then
  # checkout --force 会覆盖工作区，因此仅允许脚本管理范围内存在改动。
  UNMANAGED_CHANGES="$(git -C "$DST" status --porcelain -- . ':(exclude,top,glob)*.go' ':(exclude,top)go.mod' ':(exclude,top)go.sum' ':(exclude,top)scripts/build_android_libs.sh')"
  if [ -n "$UNMANAGED_CHANGES" ]; then
    echo "目标子模块存在脚本管理范围外的改动，拒绝切换 commit：" >&2
    echo "$UNMANAGED_CHANGES" >&2
    echo "请先提交、暂存或还原这些改动后重试。" >&2
    exit 1
  fi

  if [ "$DRY_RUN" -eq 1 ]; then
    echo "  [dry-run] fetch 源 commit 并 detached checkout: $SRC_HEAD"
  else
    echo "  对齐目标子模块 commit: $DST_HEAD -> $SRC_HEAD"
    git -C "$DST" fetch --no-tags "$SRC" "$SRC_HEAD"
    git -C "$DST" checkout --detach --force "$SRC_HEAD"
  fi
fi

# 2) 删除目标根目录中源里已不存在的 .go 文件。
shopt -s nullglob
for j in "$DST"/*.go; do
  b="$(basename "$j")"
  if [ ! -f "$SRC/$b" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
      echo "  [dry-run] 删除陈旧文件: $b"
    else
      echo "  删除陈旧文件: $b"
      rm -f "$j"
    fi
  fi
done

# 3) 复制/覆盖所有根目录 .go 文件。
for f in "$SRC"/*.go; do
  b="$(basename "$f")"
  if [ ! -f "$DST/$b" ] || ! cmp -s "$f" "$DST/$b"; then
    if [ "$DRY_RUN" -eq 1 ]; then
      echo "  [dry-run] 复制: $b"
    else
      echo "  复制: $b"
      cp -f "$f" "$DST/$b"
    fi
  fi
done
shopt -u nullglob

# 4) 同步构建/同步脚本本身，避免 Android 子模块继续使用旧的版本逻辑。
for relative_script in scripts/sync_jni.sh scripts/build_android_libs.sh; do
  if [ ! -f "$DST/$relative_script" ] || ! cmp -s "$SRC/$relative_script" "$DST/$relative_script"; then
    if [ "$DRY_RUN" -eq 1 ]; then
      echo "  [dry-run] 复制: $relative_script"
    else
      echo "  复制: $relative_script"
      cp -f "$SRC/$relative_script" "$DST/$relative_script"
    fi
  fi
done

# 5) 可选同步依赖文件，并修正跨仓库本地 replace 路径。
if [ "$WITH_MOD" -eq 1 ]; then
  command -v cygpath >/dev/null 2>&1 || {
    echo "--with-mod 需要 Git Bash 提供的 cygpath" >&2
    exit 1
  }
  command -v realpath >/dev/null 2>&1 || {
    echo "--with-mod 需要 realpath" >&2
    exit 1
  }

  for m in go.mod go.sum; do
    if [ -f "$SRC/$m" ] && { [ ! -f "$DST/$m" ] || ! cmp -s "$SRC/$m" "$DST/$m"; }; then
      if [ "$DRY_RUN" -eq 1 ]; then
        echo "  [dry-run] 同步 $m"
      else
        echo "  同步 $m"
        cp -f "$SRC/$m" "$DST/$m"
      fi
    fi
  done

  DST_POSIX="$(cygpath -u "$DST")"
  for module in github.com/NNdroid/dns_custom github.com/NNdroid/h2tunnel github.com/NNdroid/udp_custom github.com/NNdroid/xhttptunnel; do
    case "$module" in
      github.com/NNdroid/dns_custom) REPLACE_DIR="$SDK_ROOT/dns_custom" ;;
      github.com/NNdroid/h2tunnel) REPLACE_DIR="$SDK_ROOT/h2tunnel" ;;
      github.com/NNdroid/udp_custom) REPLACE_DIR="$SDK_ROOT/udp_custom" ;;
      github.com/NNdroid/xhttptunnel) REPLACE_DIR="$SDK_ROOT/xhttptunnel" ;;
    esac
    REPLACE_POSIX="$(cygpath -u "$REPLACE_DIR")"
    if [ ! -d "$REPLACE_POSIX" ]; then
      echo "本地依赖目录不存在: $REPLACE_DIR" >&2
      exit 1
    fi
    RELATIVE_REPLACE="$(realpath --relative-to="$DST_POSIX" "$REPLACE_POSIX")"
    if [ "$DRY_RUN" -eq 1 ]; then
      echo "  [dry-run] replace $module => $RELATIVE_REPLACE"
    else
      (cd "$DST" && go mod edit "-replace=$module=$RELATIVE_REPLACE")
    fi
  done
else
  for m in go.mod go.sum; do
    if [ -f "$SRC/$m" ] && { [ ! -f "$DST/$m" ] || ! cmp -s "$SRC/$m" "$DST/$m"; }; then
      echo "  [提示] $m 未同步；依赖有变动时请加 --with-mod"
    fi
  done
fi

if [ "$DRY_RUN" -eq 1 ]; then
  echo "==> dry-run 完成，未修改任何文件。"
  exit 0
fi

ACTUAL_DST_HEAD="$(git -C "$DST" rev-parse HEAD)"
if [ "$ACTUAL_DST_HEAD" != "$SRC_HEAD" ]; then
  echo "目标子模块 commit 未对齐：期望 $SRC_HEAD，实际 $ACTUAL_DST_HEAD" >&2
  exit 1
fi

echo "==> 校验 Android/arm64 Go 依赖..."
if ! (cd "$DST" && CGO_ENABLED=0 GOOS=android GOARCH=arm64 go list -mod=readonly -deps . >/dev/null); then
  if [ "$WITH_MOD" -eq 0 ]; then
    echo "依赖校验失败；请使用 --with-mod 同步并重写本地 SDK 依赖。" >&2
  fi
  exit 1
fi

echo "==> 完成。目标子模块 commit: $ACTUAL_DST_HEAD"
echo "请在 Stun 仓库提交 core/jni/myssh 子模块指针，然后重新构建 AAR。"
