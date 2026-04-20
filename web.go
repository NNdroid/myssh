package myssh

import (
	"bufio"
	"context"
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// 🌟 使用 embed 嵌入 web 资源
//
//go:embed web/*
var webFS embed.FS

var webLogServer *http.Server

type logCache struct {
	mu          sync.RWMutex
	content     []byte
	lastOffset  int64
	lastFetch   time.Time
	cacheExpiry time.Duration
}

var logCacheManager *logCache

func init() {
	logCacheManager = &logCache{
		cacheExpiry: 1 * time.Second,
	}
}

func (lc *logCache) getLogContentCached(logPath string) ([]byte, error) {
	lc.mu.RLock()
	if time.Since(lc.lastFetch) < lc.cacheExpiry && len(lc.content) > 0 {
		defer lc.mu.RUnlock()
		return lc.content, nil
	}
	lc.mu.RUnlock()

	data, err := os.ReadFile(logPath)
	if err != nil {
		return nil, err
	}

	lc.mu.Lock()
	lc.content = data
	lc.lastFetch = time.Now()
	lc.lastOffset = int64(len(data))
	lc.mu.Unlock()

	return data, nil
}

func (lc *logCache) getLogIncrementalCached(logPath string) ([]byte, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	lc.mu.RLock()
	lastOffset := lc.lastOffset
	lc.mu.RUnlock()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if info.Size() <= lastOffset {
		return []byte{}, nil
	}

	file.Seek(lastOffset, 0)
	buf := make([]byte, info.Size()-lastOffset)
	if _, err := file.Read(buf); err != nil {
		return nil, err
	}

	lc.mu.Lock()
	lc.lastOffset = info.Size()
	lc.lastFetch = time.Now()
	lc.mu.Unlock()

	return buf, nil
}

func (lc *logCache) resetCache() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.content = []byte{}
	lc.lastOffset = 0
	lc.lastFetch = time.Time{}
}

func StartWebLogger(port int, logPath string) {
	if webLogServer != nil {
		if zlog != nil {
			zlog.Warnf("%s [WebLog] Web 日志监控已在运行中，请勿重复启动", TAG)
		}
		return
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(rateLimitMiddleware())

	// 🌟 优化：将 /api/v1 归为一个路由组
	apiV1 := router.Group("/api/v1")
	{
		// 日志读取接口
		apiV1.GET("/log-raw", func(c *gin.Context) {
			mode := c.DefaultQuery("mode", "full")
			var data []byte
			var err error

			if mode == "incremental" {
				data, err = logCacheManager.getLogIncrementalCached(logPath)
			} else {
				data, err = logCacheManager.getLogContentCached(logPath)
			}

			if err != nil {
				c.String(http.StatusInternalServerError, "无法读取日志文件: %v", err)
				return
			}

			c.Data(http.StatusOK, "text/plain; charset=utf-8", data)
		})

		// 日志统计接口
		apiV1.GET("/log-stats", func(c *gin.Context) {
			file, err := os.Open(logPath)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "无法打开日志文件"})
				return
			}
			defer file.Close()

			info, _ := file.Stat()

			scanner := bufio.NewScanner(file)
			lineCount := 0
			for scanner.Scan() {
				lineCount++
			}

			c.JSON(http.StatusOK, gin.H{
				"file_size":     info.Size(),
				"line_count":    lineCount,
				"last_modified": info.ModTime(),
			})
		})

		// 清空日志接口
		apiV1.POST("/log-clear", func(c *gin.Context) {
			if err := os.Truncate(logPath, 0); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "无法清空日志"})
				return
			}
			logCacheManager.resetCache()
			c.JSON(http.StatusOK, gin.H{"message": "日志已清空"})
		})
	}

	// 🌟 提供 web 目录下的所有静态文件
	webSubFS, _ := fs.Sub(webFS, "web")
	fileServer := http.FileServer(http.FS(webSubFS))

	router.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		// 如果是请求 /api/ 开头的路径却走到了这里，说明 API 路径写错了，直接返回 JSON 报错
		if strings.HasPrefix(path, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "API route not found"})
			return
		}

		// 其他非 API 的请求，统统交给静态文件服务器处理
		// 这样既能访问根目录的 index.html，也能访问 js/css 等静态资源
		fileServer.ServeHTTP(c.Writer, c.Request)
	})

	addr := fmt.Sprintf("0.0.0.0:%d", port)

	webLogServer = &http.Server{
		Addr:           addr,
		Handler:        router,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		IdleTimeout:    30 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	if zlog != nil {
		zlog.Infof("%s [WebLog] 🌐 Web 日志监控已启动: http://%s/", TAG, addr)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := webLogServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			if zlog != nil {
				zlog.Errorf("%s [WebLog] Web 服务异常退出: %v", TAG, err)
			}
		}
	}()
}

func StopWebLogger() {
	if webLogServer != nil {
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

		webLogServer = nil
	} else {
		if zlog != nil {
			zlog.Warnf("%s [WebLog] Web 服务未运行，无需停止", TAG)
		}
	}
}

// 限流中间件
func rateLimitMiddleware() gin.HandlerFunc {
	limiters := make(map[string]*rateLimiter)
	var mu sync.Mutex

	return func(c *gin.Context) {
		mu.Lock()
		ip := c.ClientIP()
		limiter, exists := limiters[ip]
		if !exists {
			limiter = newRateLimiter(10, time.Second)
			limiters[ip] = limiter
		}
		mu.Unlock()

		if !limiter.allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "请求过于频繁"})
			c.Abort()
			return
		}
		c.Next()
	}
}

type rateLimiter struct {
	tokens     float64
	maxTokens  float64
	lastTime   time.Time
	mu         sync.Mutex
	refillRate float64
}

func newRateLimiter(maxTokens float64, period time.Duration) *rateLimiter {
	return &rateLimiter{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		lastTime:   time.Now(),
		refillRate: maxTokens / period.Seconds(),
	}
}

func (rl *rateLimiter) allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastTime).Seconds()
	rl.tokens = min(rl.maxTokens, rl.tokens+elapsed*rl.refillRate)
	rl.lastTime = now

	if rl.tokens >= 1 {
		rl.tokens--
		return true
	}
	return false
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
