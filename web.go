package myssh

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

// 定义一个包级别的变量来保存 HTTP Server 实例
var webLogServer *http.Server

// StartWebLogger 启动一个迷你的 HTTP 服务器来在浏览器展示日志
// port: Web 界面监听的端口 (例如 8888)
// logPath: 之前传入 InitLogger 的那个日志文件绝对路径
func StartWebLogger(port int, logPath string) {
	// 如果已经启动了，避免重复启动
	if webLogServer != nil {
		if zlog != nil {
			zlog.Warnf("%s [WebLog] Web 日志监控已在运行中，请勿重复启动", TAG)
		}
		return
	}

	// 设置 Gin 为发布模式，避免在终端打印多余的请求路由日志
	gin.SetMode(gin.ReleaseMode)

	// 创建一个没有任何默认中间件的路由引擎
	router := gin.New()
	router.Use(gin.Recovery())

	// 1. 提供一个酷炫的 HTML 前端页面
	router.GET("/log-ui", func(c *gin.Context) {
		html := `<!DOCTYPE html>
<html>
<head>
    <title>GoMySsh 实时日志监控</title>
    <meta charset="utf-8">
    <style>
        body { background-color: #1e1e1e; color: #4af626; font-family: Consolas, monospace; padding: 20px; font-size: 14px; line-height: 1.5; }
        #logs { white-space: pre-wrap; word-wrap: break-word; }
        .footer { position: fixed; bottom: 10px; right: 20px; color: #888; font-size: 12px; }
    </style>
</head>
<body>
    <div id="logs">日志加载中...</div>
    <div class="footer">Auto-refreshing every 2 seconds</div>
    <script>
        function fetchLogs() {
            // 请求原始日志数据
            fetch('/log-raw')
                .then(response => response.text())
                .then(text => {
                    const logDiv = document.getElementById('logs');
                    const isScrolledToBottom = window.innerHeight + window.scrollY >= document.body.offsetHeight - 50;
                    
                    logDiv.textContent = text;
                    
                    if (isScrolledToBottom) {
                        window.scrollTo(0, document.body.scrollHeight);
                    }
                })
                .catch(err => console.error("读取日志失败", err));
        }
        setInterval(fetchLogs, 2000);
        fetchLogs();
    </script>
</body>
</html>`
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
	})

	// 2. 提供一个原始日志读取接口 (供前端 JS 调用)
	router.GET("/log-raw", func(c *gin.Context) {
		data, err := os.ReadFile(logPath)
		if err != nil {
			c.String(http.StatusInternalServerError, "无法读取日志文件: %v", err)
			return
		}
		c.Data(http.StatusOK, "text/plain; charset=utf-8", data)
	})

	addr := fmt.Sprintf("0.0.0.0:%d", port)

	// 3. 实例化标准的 http.Server，挂载 Gin 路由
	webLogServer = &http.Server{
		Addr:    addr,
		Handler: router,
	}

	if zlog != nil {
		zlog.Infof("%s [WebLog] 🌐 Web 日志监控已启动: http://%s/log-ui", TAG, addr)
	}

	// 4. 在后台协程启动 Web 服务
	go func() {
		// ListenAndServe 会阻塞，必须放在协程里
		// 当我们主动调用 Shutdown 时，会返回 http.ErrServerClosed 错误，这是正常现象需要过滤掉
		if err := webLogServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			if zlog != nil {
				zlog.Errorf("%s [WebLog] Web 服务异常退出: %v", TAG, err)
			}
		}
	}()
}

// StopWebLogger 停止 Web 日志展示服务
func StopWebLogger() {
	if webLogServer != nil {
		// 设置一个 5 秒的超时时间进行优雅关闭 (等待处理中的请求完成)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := webLogServer.Shutdown(ctx); err != nil {
			if zlog != nil {
				zlog.Errorf("%s [WebLog] ❌ Web 服务关闭异常: %v", TAG, err)
			}
		} else {
			if zlog != nil {
				zlog.Infof("%s [WebLog] 🛑 Web 日志监控已安全停止", TAG)
			}
		}
		
		// 重置实例，允许后续再次调用 StartWebLogger
		webLogServer = nil
	} else {
		if zlog != nil {
			zlog.Warnf("%s [WebLog] Web 服务未运行，无需停止", TAG)
		}
	}
}