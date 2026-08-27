//go:build tools
// +build tools

package myssh

//  info  go mod tidy  info  gomobile  info ，
//  info  Android JAR  info 。
import (
	_ "golang.org/x/mobile/bind"
	_ "golang.org/x/mobile/cmd/gobind"
	_ "golang.org/x/mobile/cmd/gomobile"
)
