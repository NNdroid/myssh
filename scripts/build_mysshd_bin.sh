#!/bin/bash
# -e：任何未受检命令失败立即退出；编译失败在 if 条件里受检，不会中断循环，
# 由结尾的 FAILED 汇总决定退出码（此前编译失败不影响退出码，CI 会误报成功）。
set -euo pipefail

# ==========================================
# 配置区域
# ==========================================
APP_NAME="mysshd"
MAIN_PATH="./web"
OUT_DIR="./bin"

# ==========================================
# 定义目标架构矩阵 (OS/ARCH)
# ==========================================
TARGETS=(
    "linux/amd64"    
    "linux/arm64"    
    "linux/arm"      
    # --- MIPS 家族 ---
    # "linux/mipsle"   # modernc.org/sqlite 不支持 MIPS 架构, 暂时移除
    # "linux/mips"     
    # "linux/mips64le" 
    # "linux/mips64"   
    # ------------------------
    "windows/amd64"  
    "darwin/amd64"
    "darwin/arm64"
)

echo "🧹 清理旧的构建文件..."
rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

echo "🚀 开始交叉编译 Web 面板，目标文件将输出到 ${OUT_DIR}/"
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
    
    printf "⏳ 正在编译: %-15s " "${GOOS}/${GOARCH}"
    
    # 执行编译命令（放进 if 条件，失败由 FAILED 记账）
    # 由于 modernc.org/sqlite 不支持 MIPS，已移除软浮点相关的逻辑
    if env CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" \
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
echo "🎉 所有 Web 面板编译任务完成！"
