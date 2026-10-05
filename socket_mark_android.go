//go:build android

package myssh

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// socketMarkClient 与 root 侧的 `sockmark` 辅助进程通信，请求为隧道 socket 打 SO_MARK。
//
// 背景
// ----
// tproxy 模式下 iptables 会把出站流量 TPROXY 回本地 socks5（hev-socks5-tproxy 监听
// 127.0.0.1:10808），而那个 socks5 的上游正是本进程监听的 SOCKS5 服务（engine.go 的
// socks5.NewClassicServer(cfg.LocalAddr)）。若 myssh 自己拨出去的 SSH socket 也被 TPROXY
// 抓走，流量就会回到自己 —— 死循环。
//
// 传统解法是把整个 App 加进 tproxy 的 bypass 列表（按 uid）。但那太粗：App 内的
// WebUI / MCP / 出口 IP 探测等流量本来应该走隧道，却被迫直连，出口 IP 永远显示本机地址。
//
// 精确解法是只给隧道 socket 打 SO_MARK，让 tproxy.sh 按 mark 放行。
// 但 setsockopt(SO_MARK) 需要 CAP_NET_ADMIN，而 App 进程没有 —— 调用会 EPERM。
// 所以只能让 root 进程代设：`sockmark` 辅助进程经 pidfd_getfd 借到本进程的 fd 后设 mark。
//
// 生命周期
// --------
// helper 由 App 侧（Kotlin, root shell）以 `sockmark <app_pid>` 启动，通过一对 pipe 与之通信。
// 本文件只负责在拿到 socket fd 后发请求并等 ACK；helper 挂了会自动懒重启。
type socketMarkClient struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	stdin    *os.File // 写请求
	stdout   *bufio.Reader
	exePath  string
	appPID   int
	markVal  int
	disabled bool // helper 不可用时置位，避免每次拨号都重试拖慢
}

var (
	globalMarkClient   *socketMarkClient
	globalMarkClientMu sync.Mutex
)

// RegisterSocketMarkHelper 由宿主（Kotlin）在 sockmark 辅助进程就绪后调用。
//
// appPID 传 0 表示"自行探测"（读 os.Getpid()），辅助进程需要它来定位本进程的 fd。
//
// ⚠️ 参数一律用 int64：gomobile 把 Go 的整数映射成 Java `long`（恒 64 位），
// 若这里声明成 `int`，在 32 位 ABI（armeabi-v7a / x86）上经 JNI 传参会**截断**。
func RegisterSocketMarkHelper(exePath string, appPID int64, mark int64) {
	globalMarkClientMu.Lock()
	defer globalMarkClientMu.Unlock()

	if exePath == "" || mark == 0 {
		globalMarkClient = nil
		zlog.Infof("%s [Mark] ⚠️ Socket mark helper disabled (exe=%q mark=%d)", TAG, exePath, mark)
		return
	}
	if appPID <= 0 {
		appPID = int64(os.Getpid())
	}
	globalMarkClient = &socketMarkClient{
		exePath: exePath,
		appPID:  int(appPID),
		markVal: int(mark),
	}
	zlog.Infof("%s [Mark] 🔧 Socket mark helper registered (exe=%s pid=%d mark=0x%x)", TAG, exePath, appPID, mark)
}

// markSocketFD 请求为指定 fd 打 mark。失败只记录日志、绝不中断拨号 ——
// 隧道能不能建起来不取决于 mark，mark 只决定"是否被 TPROXY 抓"。
func markSocketFD(fd uintptr) {
	globalMarkClientMu.Lock()
	c := globalMarkClient
	globalMarkClientMu.Unlock()
	if c == nil || c.disabled {
		return
	}
	if err := c.request(fd); err != nil {
		// 连不上 helper（没启动 / 已退出）时标记为不可用，避免每次拨号都 fork 一次。
		// 下次连接时 RegisterSocketMarkHelper 会重新建立。
		zlog.Warnf("%s [Mark] ⚠️ mark request failed (fd=%d): %v — further marks disabled for this session", TAG, fd, err)
		c.disable()
	}
}

// ProbeSocketMark 真正跑一次 mark 通路，确认「App 能借到自己的 fd 并让 root 成功设上 mark」。
//
// 为什么需要它：helper 是 App 自己 fork、经 su 提权的，中间任何一环都可能失败 ——
// 设备没 root、su 不在候选路径、内核 <5.6 没有 pidfd_getfd、某些 ROM 的 ptrace 策略
// 拦下跨进程借 fd。这些失败在拨号时只会表现为「SSH 连不上」，**根因极难定位**。
// 所以在拨号之前先探一次：能设上才让规则侧走 mark 模式，设不上就老老实实回落到
// uid 放行（代价是 App 内流量全直连，但至少隧道能连）。
//
// 实现上造一个真实的 AF_INET socket 并请 helper 打 mark —— 只做 setsockopt，不 connect、
// 不发包，因此不产生任何网络流量。
//
// 诊断分四段打日志（[Mark-Diag] 前缀，便于 `adb logcat | grep Mark-Diag` 一把捞全）：
//
//	阶段 1  自身能力：euid / helper 二进制存在性与可执行位 / 各 su 候选路径的探测结果
//	阶段 2  helper 能否以 root 起来：实际用的 su 路径、helper pid
//	阶段 3  协议往返：PING 是否通（区分"进程没起来"与"起来了但不响应"）
//	阶段 4  真正的 setsockopt：内核给的 errno（EPERM=没 CAP_NET_ADMIN、ENOSYS=内核太老、
//	           ESRCH=App 进程不在、EINVAL=fd 不对）
//
// 返回值：1 = 通路可用；0 = 不可用（已记日志，调用方应回落到 uid 放行）。
func ProbeSocketMark() int64 {
	globalMarkClientMu.Lock()
	c := globalMarkClient
	globalMarkClientMu.Unlock()
	if c == nil {
		zlog.Warnf("%s [Mark-Diag] 阶段1 失败：没有注册 helper（Kotlin 侧没调 RegisterSocketMarkHelper，"+
			"或 exePath 为空 / mark=0 被当成禁用）", TAG)
		return 0
	}

	// ── 阶段 1：自身能力 ────────────────────────────────────────────────
	zlog.Infof("%s [Mark-Diag] ══ 阶段1 自身能力 ══", TAG)
	zlog.Infof("%s [Mark-Diag]   app_pid=%d  mark=0x%x  euid=%d (0=已是root 1000=普通App)", TAG, c.appPID, c.markVal, os.Geteuid())
	if fi, err := os.Stat(c.exePath); err != nil {
		zlog.Warnf("%s [Mark-Diag]   helper 不可达：%v —— 检查 AppBootstrap 是否部署成功", TAG, err)
	} else {
		mode := fi.Mode()
		zlog.Infof("%s [Mark-Diag]   helper 存在：%s  size=%d  mode=%s  可执行=%v",
			TAG, c.exePath, fi.Size(), mode.String(), mode.Perm()&0111 != 0)
	}
	if os.Geteuid() != 0 {
		// 非 root 时必须走 su。把每个候选的探测结果都打出来 ——
		// 之前只在"全失败"时给一个汇总错误，根本看不出是哪个路径不存在。
		found := ""
		for _, su := range suCandidates {
			if p, err := exec.LookPath(su); err == nil {
				zlog.Infof("%s [Mark-Diag]   su 候选可用：%-24s → %s", TAG, su, p)
				if found == "" {
					found = su
				}
			} else {
				zlog.Infof("%s [Mark-Diag]   su 候选缺失：%-24s (%v)", TAG, su, err)
			}
		}
		if found == "" {
			zlog.Warnf("%s [Mark-Diag]   ⚠️ 没有任何 su 路径可用 ⇒ helper 必然以非 root 运行 ⇒ setsockopt 必 EPERM。"+
				"本机是否 root？Magisk/KernelSU 是否安装？", TAG)
		}
	} else {
		zlog.Infof("%s [Mark-Diag]   euid=0，跳过 su 直接以 root 拉起 helper", TAG)
	}

	// ── 阶段 2/3：helper 启动 + 协议往返 ───────────────────────────────
	zlog.Infof("%s [Mark-Diag] ══ 阶段2/3 启动 helper 并验证协议 ══", TAG)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		zlog.Warnf("%s [Mark-Diag] 探测 socket 创建失败：%v", TAG, err)
		return 0
	}
	defer syscall.Close(fd)

	if err := c.probeRoundTrip(uintptr(fd)); err != nil {
		zlog.Warnf("%s [Mark-Diag] 阶段3/4 失败：%v", TAG, err)
		zlog.Warnf("%s [Mark-Diag] ══ 结论：SO_MARK 不可用 ⇒ 将回落到 uid 放行（App 内流量全部直连）══", TAG)
		return 0
	}

	// ── 阶段 4：回读验证 ───────────────────────────────────────────────
	zlog.Infof("%s [Mark-Diag] ══ 阶段4 setsockopt + GET 回读 ══", TAG)
	if got, err := c.readBackMark(uintptr(fd)); err != nil {
		zlog.Warnf("%s [Mark-Diag]   GET 回读失败：%v（不影响结论：MARK 已返回 OK）", TAG, err)
	} else if int(got) != c.markVal {
		zlog.Warnf("%s [Mark-Diag]   ⚠️ 回读值 %d(0x%x) 与期望 %d(0x%x) 不一致 —— helper 可能在别的 netns 里设的 mark",
			TAG, got, got, c.markVal, c.markVal)
	} else {
		zlog.Infof("%s [Mark-Diag]   回读一致：mark=0x%x 真的落在 socket 上", TAG, got)
	}

	zlog.Infof("%s [Mark-Diag] ══ 结论：SO_MARK 通路可用，隧道 socket 将按 mark 精确放行 ══", TAG)
	return 1
}

// probeRoundTrip 先 PING 验协议、再 MARK 验权限，把两类失败分开报。
func (c *socketMarkClient) probeRoundTrip(fd uintptr) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureLocked(); err != nil {
		return fmt.Errorf("拉起 helper 失败: %w", err)
	}
	zlog.Infof("%s [Mark-Diag]   helper 已启动（记住上面 launched via 那一行的 su 路径）", TAG)

	// PING 不碰权限，纯粹验协议：能回 PONG 说明进程活着且管道通。
	// 这一步把"helper 没起来"与"起来了但 setsockopt 被拒"区分开 ——
	// 两者的根因与修法完全不同，混成一句 ERR 就没法排查了。
	if _, err := fmt.Fprintf(c.stdin, "PING\n"); err != nil {
		c.closeLocked()
		return fmt.Errorf("写 PING 失败（管道不通）: %w", err)
	}
	line, err := c.stdout.ReadString('\n')
	if err != nil {
		c.closeLocked()
		return fmt.Errorf("读 PING 响应失败（helper 可能已崩溃，或 su 未真正提权）: %w", err)
	}
	if got := strings.TrimSpace(line); !strings.HasPrefix(got, "PONG") {
		return fmt.Errorf("PING 响应异常: %q", got)
	}
	zlog.Infof("%s [Mark-Diag]   PING/PONG 正常 ⇒ 管道通、helper 活着", TAG)

	if _, err := fmt.Fprintf(c.stdin, "MARK %d %d\n", fd, c.markVal); err != nil {
		c.closeLocked()
		return fmt.Errorf("写 MARK 失败: %w", err)
	}
	line, err = c.stdout.ReadString('\n')
	if err != nil {
		c.closeLocked()
		return fmt.Errorf("读 MARK 响应失败: %w", err)
	}
	if got := strings.TrimSpace(line); got != "OK" {
		return fmt.Errorf("helper 拒绝设 mark: %s —— "+
			"EPERM=helper 没有 CAP_NET_ADMIN（su 没真提权，或 SELinux 拦了）、"+
			"ESRCH=%d 进程已死、ENOSYS=内核不支持所需 syscall", got, c.appPID)
	}
	zlog.Infof("%s [Mark-Diag]   MARK 返回 OK", TAG)
	return nil
}

// readBackMark 用 GET 回读 mark 值。getsockopt 不需要特权，所以这是独立验证。
func (c *socketMarkClient) readBackMark(fd uintptr) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := fmt.Fprintf(c.stdin, "GET %d\n", fd); err != nil {
		return 0, err
	}
	line, err := c.stdout.ReadString('\n')
	if err != nil {
		return 0, err
	}
	var v int
	if n, serr := fmt.Sscanf(strings.TrimSpace(line), "MARK %d", &v); serr != nil || n != 1 {
		return 0, fmt.Errorf("GET 响应异常: %q", strings.TrimSpace(line))
	}
	return int64(v), nil
}

func (c *socketMarkClient) disable() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.disabled = true
	c.closeLocked()
}

func (c *socketMarkClient) closeLocked() {
	if c.stdin != nil {
		c.stdin.Close()
		c.stdin = nil
	}
	if c.cmd != nil && c.cmd.Process != nil {
		c.cmd.Process.Kill()
		c.cmd.Wait()
		c.cmd = nil
	}
	c.stdout = nil
}

// ensureLocked 惰性拉起 helper 进程并接上管道。
func (c *socketMarkClient) ensureLocked() error {
	if c.stdout != nil {
		return nil
	}
	if _, err := os.Stat(c.exePath); err != nil {
		return fmt.Errorf("sockmark helper not found at %s: %w", c.exePath, err)
	}

	// 用 os.Pipe 而不是 StdinPipe：StdinPipe 返回 io.WriteCloser，
	// 拿不到 *os.File，无法在出错时可靠地重建管道。
	inR, inW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("pipe for sockmark stdin: %w", err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		return fmt.Errorf("pipe for sockmark stdout: %w", err)
	}

	cmd, launched, err := buildHelperCommand(c.exePath, c.appPID, inR, outW)
	if err != nil {
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
		return fmt.Errorf("start sockmark helper (via %s): %w", launched, err)
	}
	// 父进程这边关掉多余的一端，否则 helper 退出后我们永远读不到 EOF。
	inR.Close()
	outW.Close()

	c.cmd = cmd
	c.stdin = inW
	c.stdout = bufio.NewReader(outR)
	zlog.Infof("%s [Mark] 🚀 sockmark helper started (pid=%d, launched via %s)", TAG, cmd.Process.Pid, launched)
	return nil
}

// su 的常见安装位置。Magisk / SuperSU / 各类内核都往这几个目录塞 su，
// 直接写死 `/system/bin/su` 在 KernelSU 等分支上会找不到。
var suCandidates = []string{
	"/system/bin/su",
	"/system/xbin/su",
	"/sbin/su",
	"/su/bin/su",
	"/debug_ramdisk/su",
	"su", // 兜底：走 PATH
}

// buildHelperCommand 构造拉起 helper 的命令。
//
// ⚠️ **必须经 su 提权**：setsockopt(SO_MARK) 要 CAP_NET_ADMIN，App 进程（及其 fork 出的
// 子进程）都拿不到这个 capability，直接以非 root 身份跑 helper 必然 EPERM。
//
// 为什么不在 Kotlin 侧用 RootShell 起：那个方案会让「拿到 fd」与「helper 还活着」之间出现
// 跨进程竞态窗口 —— 请求-响应必须与 socket 创建同生命周期，所以这里坚持自己 fork，
// 只把**身份**换成 root，而不是把**进程**交给别人管。
//
// 用 `exec` 前缀让 helper 替换掉 su 拉起的那个 shell：少一层进程、少一层 fd 传递，
// 也不给 shell 任何改写我们 stdio 的机会（fd 0/1 由 su 原样继承，正是我们那对 pipe）。
func buildHelperCommand(exePath string, appPID int, inR, outW *os.File) (*exec.Cmd, string, error) {
	if os.Geteuid() == 0 {
		// 极少数环境（App 自身以 root 运行，如 root 化框架下的调试）不需要绕 su。
		cmd := exec.Command(exePath, strconv.Itoa(appPID))
		cmd.Stdin = inR
		cmd.Stdout = outW
		return cmd, "direct(euid=0)", nil
	}

	var lastErr error
	for _, su := range suCandidates {
		// exePath 来自 cacheDir，多用户 / 工作资料场景下可能带空格 —— 必须给 su 的
		// 单个 -c 字符串加引号，否则它会被拆成两段而 helper 路径变错。
		// 用单引号并转义内嵌单引号：路径里出现单引号的概率极低，但转义成本也就一行。
		cmd := exec.Command(su, "-c", "exec "+shellQuote(exePath)+" "+strconv.Itoa(appPID))
		cmd.Stdin = inR
		cmd.Stdout = outW
		if _, err := exec.LookPath(su); err != nil {
			lastErr = err
			continue
		}
		return cmd, su, nil
	}
	return nil, "", fmt.Errorf("no usable su binary found (tried %v): %w", suCandidates, lastErr)
}

// shellQuote 把字符串包成单引号形式，供 `sh -c` 安全展开。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// request 发一条 MARK 请求并等 ACK。整段在锁内串行执行 ——
// 协议是行式请求/响应，并发交错会把 ACK 读串。
func (c *socketMarkClient) request(fd uintptr) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureLocked(); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(c.stdin, "MARK %d %d\n", fd, c.markVal); err != nil {
		c.closeLocked()
		return fmt.Errorf("write MARK request: %w", err)
	}

	line, err := c.stdout.ReadString('\n')
	if err != nil {
		c.closeLocked()
		return fmt.Errorf("read MARK ack: %w", err)
	}
	line = strings.TrimSpace(line)
	if line == "OK" {
		zlog.Debugf("%s [Mark] ✅ fd=%d marked with 0x%x", TAG, fd, c.markVal)
		return nil
	}
	// ERR <errno> <strerror>：helper 侧看得见具体原因，日志里保留原文便于真机定位。
	return fmt.Errorf("helper rejected: %s", line)
}

// wrapSocketMark 给 Dialer 套上 mark 请求的包装层，返回克隆后的新 Dialer。
//
// 与 wrapAndroidProtect 同样的手法：克隆并串联原 Control，不改动调用方持有的实例。
// 两个包装的顺序是 protect 在内、mark 在外 —— 它们都在同一个 fd 上动手，互不冲突。
func wrapSocketMark(dialer *net.Dialer) *net.Dialer {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	cloned := *dialer
	original := cloned.Control

	cloned.Control = func(network, address string, c syscall.RawConn) error {
		if err := androidMarkControl()(network, address, c); err != nil {
			return err
		}
		if original != nil {
			return original(network, address, c)
		}
		return nil
	}
	return &cloned
}

// androidMarkControl 返回在拿到 socket fd 后请求打 mark 的 Control 回调。
//
// 与 androidProtectControl 并联挂在同一个 Dialer 上：两者拿的是同一个 fd，
// 但作用不同 —— protect() 解决 VPN 模式的回环，mark 解决 tproxy 模式的回环。
func androidMarkControl() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, rc syscall.RawConn) error {
		// 必须包在 Control 的回调里：此刻 socket 已创建、尚未 connect，
		// 第一个 SYN 出去之前 mark 已经设好，不会被 TPROXY 半路抓走。
		// 无论成败都返回 nil：拿不到 fd 或 mark 被拒都不该让拨号失败。
		if err := rc.Control(func(fd uintptr) {
			markSocketFD(fd)
		}); err != nil {
			zlog.Warnf("%s [Mark] ⚠️ Control could not obtain fd for %s: %v", TAG, network, err)
		}
		return nil
	}
}
