//go:build !(linux && !android)

package myssh

import (
	"net"
)

// bindDevice 在非 Linux 系统下的降级处理
func bindDevice(dialer *net.Dialer, ifaceName string) {
	if ifaceName != "" {
		zlog.Warnf("%s [Tunnel] ⚠️ 当前操作系统不支持通过名称强绑定网卡 (%s)，将回退使用系统默认路由表", TAG, ifaceName)

		// 备用方案：在非 Linux 系统下，你可以尝试通过查找网卡的 IP 地址，然后绑定 IP
		// iface, err := net.InterfaceByName(ifaceName)
		// if err == nil {
		//    addrs, _ := iface.Addrs()
		//    if len(addrs) > 0 {
		//        if ipnet, ok := addrs[0].(*net.IPNet); ok {
		//            dialer.LocalAddr = &net.TCPAddr{IP: ipnet.IP}
		//            zlog.Infof("%s [Tunnel] 已回退为绑定网卡 IP: %s", TAG, ipnet.IP.String())
		//        }
		//    }
		// }
	}
}
