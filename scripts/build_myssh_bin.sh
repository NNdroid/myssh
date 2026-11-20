#!/bin/bash
# -e：任何未受检命令失败立即退出；编译失败在 if 条件里受检，不会中断循环，
# 由结尾的 FAILED 汇总决定退出码（此前编译失败不影响退出码，CI 会误报成功）。
set -euo pipefail

# ==========================================
# 配置区域
# ==========================================
APP_NAME="myssh"
MAIN_PATH="./cmd/main.go"
OUT_DIR="./bin"

# ==========================================
# 定义目标架构矩阵 (OS/ARCH)
# ==========================================
TARGETS=(
    "linux/amd64"    
    "linux/arm64"    
    "linux/arm"      
    # --- 新增的 MIPS 家族 ---
    "linux/mipsle"   # 32位小端 (最常见)
    "linux/mips"     # 32位大端
    "linux/mips64le" # 64位小端
    "linux/mips64"   # 64位大端
    # ------------------------
    "windows/amd64"  
    "darwin/amd64"   
    "darwin/arm64"   
)

echo "🧹 清理旧的构建文件..."
rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

echo "🚀 开始交叉编译，目标文件将输出到 ${OUT_DIR}/"
echo "------------------------------------------------"

FAILED=0

for target in "${TARGETS[@]}"; do
    GOOS=${target%/*}
    GOARCH=${target#*/}
    
    EXT=""
    if [ "$GOOS" = "windows" ]; then
        EXT=".exe"
    fi
    
    OUTPUT="${OUT_DIR}/${APP_NAME}_${GOOS}_${GOARCH}${EXT}"
    
    # 💡 核心逻辑：检测是否为 mips 架构，如果是，强制开启软浮点
    EXTRA_ENV=""
    if [[ "$GOARCH" == mips* ]]; then
        # mips64 需要使用 GOMIPS64 变量
        if [[ "$GOARCH" == mips64* ]]; then
            EXTRA_ENV="GOMIPS64=softfloat"
        else
            EXTRA_ENV="GOMIPS=softfloat"
        fi
        printf "⏳ 正在编译: %-15s (软浮点) " "${GOOS}/${GOARCH}"
    else
        printf "⏳ 正在编译: %-15s " "${GOOS}/${GOARCH}"
    fi
    
    # 执行编译命令，动态注入额外环境变量（放进 if 条件，失败由 FAILED 记账）
    if env CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" ${EXTRA_ENV} \
        go build -trimpath -ldflags="-s -w" -o "${OUTPUT}" "${MAIN_PATH}"; then
        echo "✅ 成功"
    else
        echo "❌ 失败"
        FAILED=1
    fi
done

echo "------------------------------------------------"
if [ "${FAILED}" -ne 0 ]; then
    echo "💥 存在编译失败的目标"
    exit 1
fi
echo "🎉 所有编译任务完成！"