#!/bin/bash

# 设置遇到错误立刻退出脚本
set -e

# ================= 配置区域 =================
# Go 源码所在的相对目录
GO_SRC_DIR="." 

# 目标输出目录 (相对于 myssh 目录，见下方 cd)
OUTPUT_DIR="../../libs"

# 生成的产物文件名
DEBUG_OUTPUT_FILE="myssh.debug.aar"
RELEASE_OUTPUT_FILE="myssh.release.aar"
DEBUG_SLIM_FILE="myssh.debug-slim.aar"
RELEASE_SLIM_FILE="myssh.release-slim.aar"
CLASSES_JAR_FILE="myssh-classes.jar"

# 完整的输出路径
DEBUG_OUTPUT_PATH="${OUTPUT_DIR}/${DEBUG_OUTPUT_FILE}"
RELEASE_OUTPUT_PATH="${OUTPUT_DIR}/${RELEASE_OUTPUT_FILE}"

# 定位 myssh 目录（脚本位于 core/jni/myssh/scripts/）并切过去，
# 否则 GO_SRC_DIR="." 和 OUTPUT_DIR="../../libs" 会在别的调用目录下解析错。
MYSSH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$MYSSH_DIR"

# 定义发版版本号：默认绑定当前 myssh 提交，允许通过环境变量 VERSION 覆盖。
# 格式与 .github/workflows/release.yml 保持一致：v1.0.YYYYMMDD-<short-hash>
# 例如：v1.0.20260920-e165d56
if [ -z "${VERSION:-}" ]; then
    BUILD_DATE="$(date -u +%Y%m%d)"
    GIT_HASH="$(git rev-parse --short=7 HEAD 2>/dev/null || true)"

    if [ -z "$GIT_HASH" ]; then
        GIT_HASH="unknown"
    fi

    VERSION="v1.0.${BUILD_DATE}-${GIT_HASH}"
fi
# ============================================


echo "🏷️  构建版本: $VERSION"
echo "🚀 开始使用 gomobile 编译..."

# 检查依赖工具。Windows 下 gomobile 带 .exe 后缀；zip/unzip 用于后面的拆包步骤。
require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" &> /dev/null; then
        echo "❌ 错误: 未检测到 $cmd 命令，请确保已安装并配置了环境变量。"
        exit 1
    fi
}

if ! command -v gomobile &> /dev/null && ! command -v gomobile.exe &> /dev/null; then
    echo "❌ 错误: 未检测到 gomobile 命令，请确保已安装并配置了环境变量。"
    exit 1
fi
require_cmd unzip
require_cmd zip

# 确保 core/libs 目录存在，如果不存在则自动创建
if [ ! -d "$OUTPUT_DIR" ]; then
    echo "📂 目录 $OUTPUT_DIR 不存在，正在创建..."
    mkdir -p "$OUTPUT_DIR"
fi

go mod tidy
# 正式版
LDFLAGS="-s -w -X 'myssh.Version=$VERSION' -X 'myssh.DebugStr=false'"
echo "📦 正在编译并打包至 $RELEASE_OUTPUT_PATH ..."
# 在 Git Bash 等环境中，相对路径 "../../libs" 能被原生的 gomobile.exe 完美识别
gomobile bind -v -target=android -androidapi 28 -ldflags="$LDFLAGS" -trimpath -o "$RELEASE_OUTPUT_PATH" "$GO_SRC_DIR"
# 检查编译结果
if [ -f "$RELEASE_OUTPUT_PATH" ]; then
    echo "✅ 编译成功！"
    echo "📄 AAR 文件已成功保存到: $RELEASE_OUTPUT_PATH"
else
    echo "❌ 编译失败: 未能在预期位置找到生成的文件。"
    exit 1
fi

# 临时调试版本
LDFLAGS="-X 'myssh.Version=$VERSION' -X 'myssh.DebugStr=true'"
echo "📦 正在编译带调试符号的版本..."
gomobile bind -v -target=android -androidapi 28 -ldflags="$LDFLAGS" -o "$DEBUG_OUTPUT_PATH" "$GO_SRC_DIR"

# 检查编译结果
if [ -f "$DEBUG_OUTPUT_PATH" ]; then
    echo "✅ 编译成功！"
    echo "📄 AAR 文件已成功保存到: $DEBUG_OUTPUT_PATH"
else
    echo "❌ 编译失败: 未能在预期位置找到生成的文件。"
    exit 1
fi

# ====================================================================
# 拆包：生成 core/libs 下 gradle 真正消费的两类产物
#
# 胖 AAR 同时含 classes.jar 和 jni/*.so。若直接依赖，类会与单独引入的
# classes.jar 重复，导致 duplicate-class。所以拆成：
#   myssh-classes.jar   —— 编译期类（release/debug 绑定类相同，共享一份）
#   myssh.*-slim.aar    —— 运行期包：原包去掉 classes.jar，其余条目原样保留
#
# 用 zip -d 原地删条目而不是解包重打：其余条目的压缩数据原样保留（省掉
# 4 个 .so 的重新压缩），产物结构与 CI 一致。zip -r 在 Windows 版 zip 下
# 会额外写入 jni/ 之类的目录条目。
# ====================================================================
echo "🧩 拆包生成 classes.jar 与 slim AAR..."

for VARIANT in release debug; do
    AAR="${OUTPUT_DIR}/myssh.${VARIANT}.aar"
    if [ "$VARIANT" = "release" ]; then
        SLIM="${OUTPUT_DIR}/${RELEASE_SLIM_FILE}"
    else
        SLIM="${OUTPUT_DIR}/${DEBUG_SLIM_FILE}"
    fi

    if [ ! -f "$AAR" ]; then
        echo "❌ 错误: 缺少输入 AAR $AAR"
        exit 1
    fi

    # 只从 release 取一份 classes.jar（两者绑定类完全相同）
    if [ "$VARIANT" = "release" ]; then
        unzip -p "$AAR" classes.jar > "${OUTPUT_DIR}/${CLASSES_JAR_FILE}"
    fi

    cp "$AAR" "$SLIM"
    zip -q -d "$SLIM" classes.jar
done

echo "📦 core/libs 产物清单:"
ls -la \
    "${OUTPUT_DIR}/${CLASSES_JAR_FILE}" \
    "${OUTPUT_DIR}/${RELEASE_SLIM_FILE}" \
    "${OUTPUT_DIR}/${DEBUG_SLIM_FILE}"
