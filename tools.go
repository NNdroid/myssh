//go:build tools
// +build tools

package myssh

// 这个文件的唯一作用是让 go mod tidy 能够追踪 gomobile 等工具的依赖，
// 它不会被编译到你的 Android JAR 中。
import (
	_ "golang.org/x/mobile/bind"
	_ "golang.org/x/mobile/cmd/gobind"
	_ "golang.org/x/mobile/cmd/gomobile"
)