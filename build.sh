#!/bin/bash

# 设置遇到错误立刻退出脚本
set -e

# ================= 配置区域 =================
# Go 源码所在的相对目录
GO_SRC_DIR="." 

# 目标输出目录 (相对于脚本运行位置)
OUTPUT_DIR="../../libs"

# 生成的 AAR 文件名
OUTPUT_FILE="myssh.aar"

# 完整的输出路径
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_FILE}"

# 定义发版版本号
VERSION="v1.0.$(date +%Y%m%d)"
# ============================================

LDFLAGS="-s -w -X 'myssh.Version=$VERSION'"

echo "🚀 开始使用 gomobile 编译..."

# 1. 检查 gomobile 环境是否安装 (增加对 Windows .exe 后缀的兼容检查)
if ! command -v gomobile &> /dev/null && ! command -v gomobile.exe &> /dev/null; then
    echo "❌ 错误: 未检测到 gomobile 命令，请确保已安装并配置了环境变量。"
    exit 1
fi

# 2. 确保 app/libs 目录存在，如果不存在则自动创建
if [ ! -d "$OUTPUT_DIR" ]; then
    echo "📂 目录 $OUTPUT_DIR 不存在，正在创建..."
    mkdir -p "$OUTPUT_DIR"
fi

go mod tidy
# 3. 执行 gomobile 编译命令
echo "📦 正在编译并打包至 $OUTPUT_PATH ..."
# 在 Git Bash 等环境中，相对路径 "../../libs" 能被原生的 gomobile.exe 完美识别
gomobile bind -v -target=android -androidapi 28 -ldflags="$LDFLAGS" -trimpath -o "$OUTPUT_PATH" "$GO_SRC_DIR"

# 4. 检查编译结果
if [ -f "$OUTPUT_PATH" ]; then
    echo "✅ 编译成功！"
    echo "📄 AAR 文件已成功保存到: $OUTPUT_PATH"
else
    echo "❌ 编译失败: 未能在预期位置找到生成的文件。"
    exit 1
fi