//go:build tools
// +build tools

package myssh

// 本文件仅用于让 go mod tidy 保留 gomobile 相关工具依赖，
// 使 Android JAR/AAR 构建可离线完成。
import (
	_ "golang.org/x/mobile/bind"
	_ "golang.org/x/mobile/cmd/gobind"
	_ "golang.org/x/mobile/cmd/gomobile"
)
