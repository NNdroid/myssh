#!/bin/bash
# 运行当前项目下的所有 Go 测试

echo "🚀 开始运行所有 Go 测试..."

# 1. 动态获取当前主机的原生系统和架构配置
export GOOS=$(go env GOHOSTOS)
export GOARCH=$(go env GOHOSTARCH)
# 获取 CGO 状态
export CGO_ENABLED=$(go env CGO_ENABLED)

echo "💻 当前测试环境已重置: GOOS=$GOOS, GOARCH=$GOARCH, CGO_ENABLED=$CGO_ENABLED"

# 2. 动态判断当前架构是否支持 -race
RACE_FLAG=""
if [ "$CGO_ENABLED" != "1" ]; then
    echo "⚠️ 当前环境 CGO_ENABLED=0，数据竞争检测 (-race) 依赖 CGO，已自动禁用。"
else
    if [ "$GOOS" == "linux" ] && [ "$GOARCH" == "amd64" ]; then
        RACE_FLAG="-race"
    elif [ "$GOOS" == "darwin" ] && [ "$GOARCH" == "amd64" ]; then
        RACE_FLAG="-race"
    elif [ "$GOOS" == "darwin" ] && [ "$GOARCH" == "arm64" ]; then
        RACE_FLAG="-race"
    elif [ "$GOOS" == "windows" ] && [ "$GOARCH" == "amd64" ]; then
        RACE_FLAG="-race"
    fi

    if [ -n "$RACE_FLAG" ]; then
        echo "🔍 检测到环境支持且 CGO 已开启，已自动开启 -race 保护"
    else
        echo "⚠️ 当前平台 ($GOOS/$GOARCH) 暂不支持 -race 参数，已自动禁用"
    fi
fi

echo "======================================"

# 3. 运行测试
go test -v $RACE_FLAG ./...

# 获取 go test 命令的退出状态码
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "======================================"
    echo "✅ 所有测试顺利通过！"
    echo "======================================"
else
    echo "======================================"
    echo "❌ 部分测试失败，请向上滚动查看详细报错信息。"
    echo "======================================"
    exit $EXIT_CODE
fi
