package myssh

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// PrintAndroidUserInfo 打印当前 Go 进程在 Android 上的底层身份信息
func PrintAndroidUserInfo() {
	// 1. 获取最底层的真实 Linux UID 和 GID
	realUid := os.Getuid()
	realGid := os.Getgid()

	// 2. 逆向推算 Android 的用户空间架构
	// Android UID 计算公式: UID = (UserID * 100000) + AppBaseID
	androidUserId := realUid / 100000
	appBaseId := realUid % 100000

	// 3. 尝试获取标准的系统用户信息
	var username, homeDir string
	u, err := user.Current()
	if err != nil {
		zlog.Warn("user.Current() failed (Normal on highly customized Android)", zap.Error(err))
		username = "unknown"
		homeDir = "unknown"
	} else {
		username = u.Username
		homeDir = u.HomeDir
	}

	// 4. 使用 zap 打印结构化日志
	zlog.Info("========== GO PROCESS USER INFO ==========",
		zap.Int("real_linux_uid", realUid),
		zap.Int("real_linux_gid", realGid),
		zap.Int("android_user_id", androidUserId),
		zap.Int("app_base_id", appBaseId),
		zap.String("username", username),
		zap.String("home_dir", homeDir),
	)
}

// CheckIfKeyEncrypted 供 Android 调用
// 返回值:
// 0 - 不需要密码
// 1 - 需要密码
// 2 - 格式错误
func CheckIfKeyEncrypted(key string) int {
	keyBytes := []byte(key)
	_, err := ssh.ParsePrivateKey(keyBytes)

	if err == nil {
		return 0
	}

	var passphraseMissingError *ssh.PassphraseMissingError
	if errors.As(err, &passphraseMissingError) {
		return 1
	}

	return 2
}

// ValidatePassphrase 示例：带密码解析并测试是否通过
func ValidatePassphrase(key string, pass string) bool {
	_, err := ssh.ParsePrivateKeyWithPassphrase([]byte(key), []byte(pass))
	return err == nil
}

type CertInfo struct {
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	NotBefore  int64  `json:"not_before"`
	NotAfter   int64  `json:"not_after"`
	SANs       string `json:"sans"`
	Raw        []byte `json:"raw_der"`
	Protocol   string `json:"protocol"`
	IsVerified bool   `json:"is_verified"`
}

// FetchCertInfo 尝试通过 TLS 或 QUIC 获取服务器证书信息
func FetchCertInfo(target string, useQUIC bool) (*CertInfo, error) {
	if target == "" {
		return nil, fmt.Errorf("empty target")
	}

	addr := target
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = target + ":443"
	}
	host, _, _ := net.SplitHostPort(addr)

	var peerCerts []*x509.Certificate
	var protocol string
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3", "http/1.1"},
	}

	if useQUIC {
		protocol = "QUIC"
		conn, err := quic.DialAddr(ctx, addr, tlsConfig, nil)
		if err != nil {
			return nil, err
		}
		defer conn.CloseWithError(0, "")
		peerCerts = conn.ConnectionState().TLS.PeerCertificates
	} else {
		protocol = "TLS"
		dialer := &net.Dialer{Timeout: 8 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		peerCerts = conn.ConnectionState().PeerCertificates
	}

	if len(peerCerts) == 0 {
		return nil, fmt.Errorf("no cert")
	}

	cert := peerCerts[0]
	_, verifyErr := cert.Verify(x509.VerifyOptions{DNSName: host})

	return &CertInfo{
		Subject:    cert.Subject.CommonName,
		Issuer:     cert.Issuer.CommonName,
		NotBefore:  cert.NotBefore.Unix(),
		NotAfter:   cert.NotAfter.Unix(),
		SANs:       strings.Join(cert.DNSNames, ","),
		Raw:        cert.Raw,
		Protocol:   protocol,
		IsVerified: verifyErr == nil,
	}, nil
}

// ==========================================
// 流量统计与系统监控 (支持 Android GoMobile 回调)
// ==========================================

var (
	globalTxTotal uint64
	globalRxTotal uint64

	lastTxTotal uint64
	lastRxTotal uint64

	currentTxRate uint64
	currentRxRate uint64

	trafficCb TrafficCallback
	sysInfoCb SysInfoCallback
)

// AddTx 增加上行流量统计 (Tx)
func AddTx(n int64) {
	atomic.AddUint64(&globalTxTotal, uint64(n))
}

// AddRx 增加下行流量统计 (Rx)
func AddRx(n int64) {
	atomic.AddUint64(&globalRxTotal, uint64(n))
}

// TrackingReader 包装 io.Reader 以便统计读取到的字节数
type TrackingReader struct {
	R   io.Reader
	Add func(int64)
}

func (t *TrackingReader) Read(p []byte) (n int, err error) {
	n, err = t.R.Read(p)
	if n > 0 && t.Add != nil {
		t.Add(int64(n))
	}
	return
}

// TrafficStats 供外部获取流量数据的结构体
type TrafficStats struct {
	TxRate  int64
	RxRate  int64
	TxTotal int64
	RxTotal int64
}

// SysStats 供外部获取系统资源信息的结构体
type SysStats struct {
	CpuPercent float64
	MemAllocMB float64
	MemSysMB   float64
	Goroutines int
}

// GetTrafficStats 供外部主动调用，获取当前流量速率和总用量
func GetTrafficStats() *TrafficStats {
	return &TrafficStats{
		TxRate:  int64(atomic.LoadUint64(&currentTxRate)),
		RxRate:  int64(atomic.LoadUint64(&currentRxRate)),
		TxTotal: int64(atomic.LoadUint64(&globalTxTotal)),
		RxTotal: int64(atomic.LoadUint64(&globalRxTotal)),
	}
}

// GetSysStats 供外部主动调用，获取当前程序的 CPU、内存及 Goroutine 占用
func GetSysStats() *SysStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return &SysStats{
		CpuPercent: getCpuPercent(),
		MemAllocMB: float64(m.Alloc) / 1024.0 / 1024.0,
		MemSysMB:   float64(m.Sys) / 1024.0 / 1024.0,
		Goroutines: runtime.NumGoroutine(),
	}
}

// TrafficCallback GoMobile 导出的安卓回调接口
type TrafficCallback interface {
	OnTrafficUpdate(txRate int64, rxRate int64, txTotal int64, rxTotal int64)
}

// SysInfoCallback GoMobile 导出的安卓回调接口
type SysInfoCallback interface {
	OnSysInfoUpdate(cpuPercent float64, memAllocMB float64, memSysMB float64, goroutines int)
}

// RegisterTrafficCallback 注册流量统计回调
func RegisterTrafficCallback(cb TrafficCallback) {
	trafficCb = cb
}

// RegisterSysInfoCallback 注册系统状态监控回调
func RegisterSysInfoCallback(cb SysInfoCallback) {
	sysInfoCb = cb
}

// 简易 CPU 计算辅助变量
var (
	lastUtime float64
	lastStime float64
	lastTime  time.Time
)

// getCpuPercent 解析 /proc/self/stat 尝试简易计算进程的 CPU 使用率
func getCpuPercent() float64 {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0.0
	}

	fields := strings.Fields(string(data))
	if len(fields) < 15 {
		return 0.0
	}

	utime, _ := strconv.ParseFloat(fields[13], 64)
	stime, _ := strconv.ParseFloat(fields[14], 64)

	now := time.Now()
	if !lastTime.IsZero() {
		timeDelta := now.Sub(lastTime).Seconds()
		if timeDelta > 0 {
			// 在 Linux/Android 中，时钟滴答通常为 100 Hz
			utimeDelta := (utime - lastUtime) / 100.0
			stimeDelta := (stime - lastStime) / 100.0

			cpuPercent := ((utimeDelta + stimeDelta) / timeDelta) * 100.0

			lastUtime = utime
			lastStime = stime
			lastTime = now

			return cpuPercent
		}
	}

	lastUtime = utime
	lastStime = stime
	lastTime = now
	return 0.0
}

func init() {
	// 后台运行 1 秒的定时器，计算速率并触发回调
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		for range ticker.C {
			// 提取当前总流量
			tTx := atomic.LoadUint64(&globalTxTotal)
			tRx := atomic.LoadUint64(&globalRxTotal)

			// 提取上一秒总流量，并替换为最新总流量
			lTx := atomic.SwapUint64(&lastTxTotal, tTx)
			lRx := atomic.SwapUint64(&lastRxTotal, tRx)

			// 计算当前 1 秒内产生的流量速率
			txRate := tTx - lTx
			rxRate := tRx - lRx

			// 更新供主动查询使用的速率
			atomic.StoreUint64(&currentTxRate, txRate)
			atomic.StoreUint64(&currentRxRate, rxRate)

			// 触发 Traffic 回调给 Android
			if trafficCb != nil {
				trafficCb.OnTrafficUpdate(int64(txRate), int64(rxRate), int64(tTx), int64(tRx))
			}

			// 触发 SysInfo 回调给 Android
			if sysInfoCb != nil {
				sys := GetSysStats()
				sysInfoCb.OnSysInfoUpdate(sys.CpuPercent, sys.MemAllocMB, sys.MemSysMB, sys.Goroutines)
			}
		}
	}()
}
