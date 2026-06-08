package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"myssh"
)

func main() {
	// 1. 定义并解析命令行参数
	confPath := flag.String("conf", "config.json", "指定配置文件的路径")
	flag.Parse()

	// 2. 读取配置文件内容
	configBytes, err := os.ReadFile(*confPath)
	if err != nil {
		fmt.Printf("[Main] ❌ 无法读取配置文件 %s: %v\n", *confPath, err)
		os.Exit(1)
	}
	configStr := string(configBytes)
	
	// 初始化日志：控制台输出 DEBUG 级别，不写文件
	// 如果你要写文件，可以改成 myssh.InitLogger("/var/log/myssh.log", "INFO")
	if logRes := myssh.InitLogger("", "DEBUG"); logRes != 0 {
		fmt.Printf("[Main] ❌ 日志系统初始化失败\n")
		os.Exit(1)
	}
	
	// 在 main 函数结束前确保日志落盘
	defer myssh.SyncLogger()

	// 3. 加载全局路由与 DNS 配置 (如果你的 JSON 包含 GlobalConfig)
	// 如果配置文件中没有全局配置字段，解析失败会返回负数，这里仅做警告不中断
	if loadRes := myssh.LoadGlobalConfigFromJson(configStr); loadRes != 0 {
		fmt.Printf("[Main] ⚠️ 全局配置加载异常或未配置，返回值: %d\n", loadRes)
	}

	// 4. 启动 SSH 代理主引擎
	if startRes := myssh.StartSshTProxy2(configStr); startRes != 0 {
		fmt.Printf("[Main] ❌ SSH 代理引擎启动失败，错误码: %d\n", startRes)
		os.Exit(1)
	}

	// 5. 监听系统级终止信号 (SIGINT, SIGTERM)
	sigCh := make(chan os.Signal, 1)
	// syscall.SIGINT 对应 Ctrl+C，syscall.SIGTERM 对应 kill 命令
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	fmt.Printf("[Main] 🚀 代理程序正在后台运行，配置文件: %s\n", *confPath)
	fmt.Printf("[Main] 💡 按 Ctrl+C 可以安全停止程序\n")

	// 6. 阻塞主线程，直到接收到退出信号
	<-sigCh
	fmt.Println("\n[Main] 🛑 接收到系统终止信号，开始清理资源...")

	// 7. 触发安全的关闭流程
	myssh.StopSshTProxy()

	// 8. 等待所有后台 goroutine 完成资源回收
	myssh.WgWait()
	
	fmt.Println("[Main] 👋 资源已彻底清理，程序安全退出。")
}