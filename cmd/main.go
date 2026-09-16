package main

import (
	"flag"
	"fmt"
	"myssh"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	// 1. 定义并解析命令行参数
	confPath := flag.String("conf", "config.json", "path to the config file")
	logLevel := flag.String("level", "debug", "Log level (debug, info, warn, error)")
	pprofAddr := flag.String("pprof", "", "pprof profiling listen address (e.g. localhost:6060)")
	flag.Parse()

	if *pprofAddr != "" {
		go func() {
			fmt.Printf("[Main] 🔍 pprof profiling server listening: http://%s/debug/pprof/\n", *pprofAddr)
			if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
				fmt.Printf("[Main] ⚠️ pprof server failed to start: %v\n", err)
			}
		}()
	}

	// 2. 读取配置文件内容
	configBytes, err := os.ReadFile(*confPath)
	if err != nil {
		fmt.Printf("[Main] ❌ cannot read config file %s: %v\n", *confPath, err)
		os.Exit(1)
	}
	configStr := string(configBytes)

	// 初始化日志：控制台输出，级别取自 -level 命令行参数（默认 debug），不写文件
	// 如果你要写文件，可以改成 myssh.InitLogger("/var/log/myssh.log", "INFO")
	if logRes := myssh.InitLogger("", strings.ToUpper(*logLevel)); logRes != 0 {
		fmt.Printf("[Main] ❌ logger initialization failed\n")
		os.Exit(1)
	}

	// 在 main 函数结束前确保日志落盘
	defer myssh.SyncLogger()

	// 3. 加载全局路由与 DNS 配置 (如果你的 JSON 包含 GlobalConfig)
	// 如果配置文件中没有全局配置字段，解析失败会返回负数，这里仅做警告不中断
	if loadRes := myssh.NewSshTProxy().LoadGlobalConfig(configStr); loadRes != 0 {
		fmt.Printf("[Main] ⚠️ global config load returned non-zero (missing or invalid): %d\n", loadRes)
	}

	// 4. 启动 SSH 代理主引擎
	if startRes := myssh.NewSshTProxy().Start(configStr); startRes != 0 {
		fmt.Printf("[Main] ❌ SSH proxy engine failed to start, error code: %d\n", startRes)
		os.Exit(1)
	}

	// 5. 监听系统级终止信号 (SIGINT, SIGTERM)
	sigCh := make(chan os.Signal, 1)
	// syscall.SIGINT 对应 Ctrl+C，syscall.SIGTERM 对应 kill 命令
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	fmt.Printf("[Main] 🚀 proxy engine running in background, config: %s\n", *confPath)
	fmt.Printf("[Main] 💡 press Ctrl+C to stop safely\n")

	// 6. 阻塞主线程，直到接收到退出信号
	<-sigCh
	fmt.Println("\n[Main] 🛑 termination signal received, cleaning up resources...")

	// 7. 触发安全的关闭流程
	myssh.NewSshTProxy().Stop()

	// 8. 等待所有后台 goroutine 完成资源回收
	myssh.NewSshTProxy().WgWait()

	fmt.Println("[Main] 👋 all resources cleaned up, exiting safely.")
}
