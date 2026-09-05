package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"go.uber.org/zap"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"myssh"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

//go:embed html/*
var webFS embed.FS

var (
	webServer        *http.Server
	proxyRunning     bool
	proxyRunningNode string // Now a string to hold UUID
	proxyMu          sync.Mutex
	wg               sync.WaitGroup
)

const TAG = "[WebApp]"

type logCache struct {
	mu          sync.RWMutex
	content     []byte
	offsets     map[string]int64 // 增量读取偏移，按客户端隔离，避免多标签页互抢
	lastFetch   time.Time
	cacheExpiry time.Duration
}

var logCacheManager *logCache

func init() {
	logCacheManager = &logCache{
		cacheExpiry: 1 * time.Second,
		offsets:     make(map[string]int64),
	}
}

var jwtSecret []byte

func init() {
	// 每次启动时生成随机的 JWT 密钥。这意味着重启服务端后，所有已登录的 Web 客户端需重新登录，安全性极高
	jwtSecret = make([]byte, 32)
	rand.Read(jwtSecret)
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
	lc.mu.Unlock()

	return data, nil
}

func (lc *logCache) getLogIncrementalCached(clientID string, logPath string) ([]byte, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	lc.mu.RLock()
	lastOffset := lc.offsets[clientID]
	lc.mu.RUnlock()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	// 文件被清空/轮转（size < lastOffset）时从头重读，而不是永远返回空。
	if lastOffset > info.Size() {
		lastOffset = 0
	}
	if info.Size() == lastOffset {
		return []byte{}, nil
	}

	if _, err := file.Seek(lastOffset, io.SeekStart); err != nil {
		return nil, err
	}
	buf := make([]byte, info.Size()-lastOffset)
	// 单次 Read 可能短读，必须 ReadFull，否则偏移照样推进导致丢日志。
	if _, err := io.ReadFull(file, buf); err != nil {
		return nil, err
	}

	lc.mu.Lock()
	lc.offsets[clientID] = info.Size()
	lc.lastFetch = time.Now()
	lc.mu.Unlock()

	return buf, nil
}

func (lc *logCache) resetCache() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.content = []byte{}
	lc.offsets = make(map[string]int64)
	lc.lastFetch = time.Time{}
}

func StartWebServer(bind string, port int, logPath string, workDir string, webUser, webPass string) {
	if webServer != nil {
		zap.L().Sugar().Infof("%s [WebServer] Web admin panel is already running, please do not start again", TAG)
		return
	}

	// Ensure workDir exists
	if err := os.MkdirAll(workDir, 0755); err != nil {
		zap.L().Sugar().Infof("%s [WebServer] ❌ Failed to create work directory: %v", TAG, err)
		return
	}

	// Download rule files to workDir
	if err := myssh.DownloadRuleFiles(workDir); err != nil {
		zap.L().Sugar().Infof("%s [WebServer] ⚠️ Failed to download rule files: %v (Using existing or skipping)", TAG, err)
	}

	// Initialize Database
	if err := InitDB(filepath.Join(workDir, "mysshd.db")); err != nil {
		zap.L().Sugar().Infof("%s [WebServer] ❌ Failed to initialize database: %v", TAG, err)
		return
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	// Parse the HTML template
	tmpl, err := template.ParseFS(webFS, "html/index.html")
	if err != nil {
		zap.L().Sugar().Fatalf("Failed to parse template: %v", err)
	}
	router.SetHTMLTemplate(tmpl)

	// Serve static files from the embedded FS
	staticFS, _ := fs.Sub(webFS, "html/static")
	router.StaticFS("/static", http.FS(staticFS))

	// Create an authorized group
	authorized := router.Group("/")

	authEnabled := webUser != "" && webPass != ""

	// 公开的鉴权状态端点：前端据此决定是否强制登录弹层。
	router.GET("/api/v1/auth-status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"enabled": authEnabled})
	})

	// Unprotected route for the single-page application
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"Timestamp": time.Now().Unix(),
		})
	})

	if authEnabled {
		if webUser == "admin" && webPass == "admin" {
			zap.L().Sugar().Infof("%s [WebServer] ⚠️ Using default admin/admin credentials — set --user/--pass before exposing this panel on a network.", TAG)
		}
		zap.L().Sugar().Infof("%s [WebServer] 🔒 JWT Authentication is ENABLED for the web panel.", TAG)

		// 开放的登录接口 (发放 JWT)
		router.POST("/api/v1/login", rateLimitMiddleware(), func(c *gin.Context) {
			var req struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
				return
			}
			if subtle.ConstantTimeCompare([]byte(req.Username), []byte(webUser)) == 1 &&
				subtle.ConstantTimeCompare([]byte(req.Password), []byte(webPass)) == 1 {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"user": req.Username,
					"exp":  time.Now().Add(24 * time.Hour).Unix(),
				})
				tokenString, err := token.SignedString(jwtSecret)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
					return
				}
				c.JSON(http.StatusOK, gin.H{"token": tokenString})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			}
		})

		// JWT 拦截中间件
		authorized.Use(func(c *gin.Context) {
			authHeader := c.GetHeader("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				c.Abort()
				return
			}
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				return jwtSecret, nil
			}, jwt.WithValidMethods([]string{"HS256"}))
			if err != nil || !token.Valid {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				c.Abort()
				return
			}
			c.Next()
		})
	}

	// Protect all API routes
	apiV1 := authorized.Group("/api/v1")
	apiV1.Use(rateLimitMiddleware())
	{
		// --- Dashboard Stats ---
		apiV1.GET("/dashboard-stats", func(c *gin.Context) {
			trafficStats := myssh.GetTrafficStats()
			sysStats := myssh.GetSysStats()
			domainActivityJSON := myssh.GetDomainActivityJSON()
			var topDomains []myssh.DomainActivity
			json.Unmarshal([]byte(domainActivityJSON), &topDomains)

			proxyMu.Lock()
			currentRunning := proxyRunning
			currentNode := proxyRunningNode
			proxyMu.Unlock()

			c.JSON(http.StatusOK, gin.H{
				"sys_cpu":       fmt.Sprintf("%.1f%%", sysStats.CpuPercent),
				"sys_mem":       fmt.Sprintf("%.0f/%.0f MB", sysStats.MemAllocMB, sysStats.MemSysMB),
				"sys_goroutine": sysStats.Goroutines,
				"tx_rate":       trafficStats.TxRate,
				"rx_rate":       trafficStats.RxRate,
				"tx_total":      trafficStats.TxTotal,
				"rx_total":      trafficStats.RxTotal,
				"active_conns":  trafficStats.ActiveConns,
				"total_conns":   trafficStats.TotalConns,
				"top_domains":   topDomains,
				"running":       currentRunning,
				"running_node":  currentNode,
			})
		})

		// --- Node Management ---
		apiV1.GET("/nodes", func(c *gin.Context) {
			profiles, err := GetProfiles()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get node list: " + err.Error()})
				return
			}
			c.JSON(http.StatusOK, profiles)
		})
		apiV1.POST("/nodes", func(c *gin.Context) {
			var profile Profile
			if err := c.ShouldBindJSON(&profile); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid node data: " + err.Error()})
				return
			}
			id, err := AddProfile(profile)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add node: " + err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "Node added", "id": id})
		})
		apiV1.PUT("/nodes/:id", func(c *gin.Context) {
			id := c.Param("id")
			var profile Profile
			if err := c.ShouldBindJSON(&profile); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid node data: " + err.Error()})
				return
			}
			if err := UpdateProfile(id, profile); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update node: " + err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "Node updated"})
		})
		apiV1.DELETE("/nodes/:id", func(c *gin.Context) {
			id := c.Param("id")
			if err := DeleteProfile(id); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete node: " + err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "Node deleted"})
		})

		// --- Import/Export ---
		apiV1.GET("/nodes/export", func(c *gin.Context) {
			profiles, err := GetProfiles()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Export failed: " + err.Error()})
				return
			}
			c.Header("Content-Disposition", "attachment; filename=myssh_profiles.json")
			c.Header("Content-Type", "application/json")
			c.JSON(http.StatusOK, profiles)
		})
		apiV1.POST("/nodes/import", func(c *gin.Context) {
			file, _, err := c.Request.FormFile("file")
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "File upload failed: " + err.Error()})
				return
			}
			defer file.Close()

			data, err := io.ReadAll(file)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file: " + err.Error()})
				return
			}

			var profiles []Profile
			if err := json.Unmarshal(data, &profiles); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format: " + err.Error()})
				return
			}

			var importedCount int
			for _, p := range profiles {
				if _, err := AddProfile(p); err == nil {
					importedCount++
				}
			}
			c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Successfully imported %d nodes", importedCount)})
		})

		// --- Settings Management ---
		apiV1.GET("/settings", func(c *gin.Context) {
			settings, err := GetSettings()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get settings: " + err.Error()})
				return
			}
			c.JSON(http.StatusOK, settings)
		})
		apiV1.POST("/settings", func(c *gin.Context) {
			var settings Settings
			if err := c.ShouldBindJSON(&settings); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid settings data: " + err.Error()})
				return
			}
			if err := UpdateSettings(settings); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update settings: " + err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "Settings updated"})
		})

		// --- Proxy Control ---
		apiV1.POST("/start", func(c *gin.Context) {
			proxyMu.Lock()
			defer proxyMu.Unlock()

			if proxyRunning {
				c.JSON(http.StatusConflict, gin.H{"error": "Proxy is already running"})
				return
			}

			var req struct {
				NodeID string `json:"node_id"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
				return
			}

			globalConfigJson, err := BuildGlobalConfigJSON(req.NodeID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build global config: " + err.Error()})
				return
			}
			// 如果不是绝对路径，先从workDir中查找，如果找不到再使用原路径，确保在web环境下也能正确加载规则文件 包含GeoSite和GeoIP
			var gConfig myssh.GlobalConfig
			if err := json.Unmarshal([]byte(globalConfigJson), &gConfig); err == nil {
				if gConfig.GeoSiteFilePath != "" && !filepath.IsAbs(gConfig.GeoSiteFilePath) {
					possiblePath := filepath.Join(workDir, gConfig.GeoSiteFilePath)
					if _, err := os.Stat(possiblePath); err == nil {
						gConfig.GeoSiteFilePath = possiblePath
					}
				}
				if _, err := os.Stat(gConfig.GeoSiteFilePath); err != nil {
					zap.L().Sugar().Infof("%s [WebServer] ❌ GeoSite file not found at %s", TAG, gConfig.GeoSiteFilePath)
				}
				if gConfig.GeoIPFilePath != "" && !filepath.IsAbs(gConfig.GeoIPFilePath) {
					possiblePath := filepath.Join(workDir, gConfig.GeoIPFilePath)
					if _, err := os.Stat(possiblePath); err == nil {
						gConfig.GeoIPFilePath = possiblePath
					}
				}
				if _, err := os.Stat(gConfig.GeoIPFilePath); err != nil {
					zap.L().Sugar().Infof("%s [WebServer] ❌ GeoIP file not found at %s", TAG, gConfig.GeoIPFilePath)
				}
				if b, err := json.Marshal(gConfig); err == nil {
					globalConfigJson = string(b)
				}
			}
			myssh.NewSshTProxy().LoadGlobalConfig(globalConfigJson)

			proxyConfigJson, err := BuildProxyConfigJSON(req.NodeID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build proxy config: " + err.Error()})
				return
			}

			if myssh.NewSshTProxy().Start(proxyConfigJson) == 0 {
				proxyRunning = true
				proxyRunningNode = req.NodeID
				c.JSON(http.StatusOK, gin.H{"message": "Proxy started"})
			} else {
				proxyRunning = false
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start proxy"})
			}
		})
		apiV1.POST("/stop", func(c *gin.Context) {
			proxyMu.Lock()
			defer proxyMu.Unlock()

			myssh.NewSshTProxy().Stop()
			proxyRunning = false
			proxyRunningNode = ""
			c.JSON(http.StatusOK, gin.H{"message": "Proxy stopped"})
		})
		apiV1.GET("/status", func(c *gin.Context) {
			proxyMu.Lock()
			defer proxyMu.Unlock()
			c.JSON(http.StatusOK, gin.H{
				"running":      proxyRunning,
				"running_node": proxyRunningNode,
			})
		})

		apiV1.POST("/loglevel", func(c *gin.Context) {
			var req struct {
				Level string `json:"level"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
				return
			}

			switch strings.ToLower(req.Level) {
			case "debug", "info", "warn", "warning", "error":
			default:
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid log level"})
				return
			}

			// 仅动态调整级别；不要重开 logger（InitLogger 会以 O_TRUNC 重建文件，清空历史日志）。
			myssh.SetLogLevel(req.Level)

			c.JSON(http.StatusOK, gin.H{"message": "Log level updated to " + req.Level})
		})

		// --- Log Management ---
		apiV1.GET("/log-raw", func(c *gin.Context) {
			mode := c.DefaultQuery("mode", "full")
			clientID := c.Query("client")
			if clientID == "" {
				clientID = c.ClientIP()
			}
			var data []byte
			var err error

			if mode == "incremental" {
				data, err = logCacheManager.getLogIncrementalCached(clientID, logPath)
			} else {
				data, err = logCacheManager.getLogContentCached(logPath)
			}

			if err != nil {
				c.String(http.StatusInternalServerError, "Failed to read log file: %v", err)
				return
			}
			c.Data(http.StatusOK, "text/plain; charset=utf-8", data)
		})
		apiV1.POST("/log-clear", func(c *gin.Context) {
			// 通过重开 logger 来清空：InitLogger 以 O_TRUNC 重建文件并把写句柄归零。
			// 若只从外部截断文件，zap 已打开的句柄偏移不会重置，后续写入会产生
			// 一段 NUL 空洞（日志视图显示乱码）。
			myssh.InitLogger(logPath, myssh.GetLogLevel())

			logCacheManager.resetCache()
			c.JSON(http.StatusOK, gin.H{"message": "Logs cleared"})
		})
	}

	router.NoRoute(func(c *gin.Context) {
		// API 路径必须返回 JSON 404，不能兜底成 index.html——那会把前端的路由拼写
		// 错误伪装成 200 响应，导致 res.json() 抛错且难以排查。
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
			return
		}
		// Redirect all other requests to the root to let the single-page app handle routing
		c.HTML(http.StatusOK, "index.html", gin.H{
			"Timestamp": time.Now().Unix(),
		})
	})

	addr := fmt.Sprintf("%s:%d", bind, port)

	webServer = &http.Server{
		Addr:    addr,
		Handler: router,
	}

	zap.L().Sugar().Infof("%s [WebServer] 🌐 Web admin panel started: http://%s/", TAG, addr)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := webServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			zap.L().Sugar().Infof("%s [WebServer] Web service exited abnormally: %v", TAG, err)
		}
	}()
}

func StopWebServer() {
	if webServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := webServer.Shutdown(ctx); err != nil {
			zap.L().Sugar().Infof("%s [WebServer] ❌ Web service shutdown exception: %v", TAG, err)
		} else {
			zap.L().Sugar().Infof("%s [WebServer] 🛑 Web admin panel safely stopped", TAG)
		}
		webServer = nil
	}
}

// --- 限流中间件 ---
const (
	rateLimiterIdleTTL   = 10 * time.Minute
	rateLimiterSweepSize = 1024
)

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
		// 周期性淘汰长时间未活跃的 IP，防止 map 无限增长。
		if len(limiters) > rateLimiterSweepSize {
			now := time.Now()
			for k, v := range limiters {
				if now.Sub(time.Unix(0, v.lastSeen.Load())) > rateLimiterIdleTTL {
					delete(limiters, k)
				}
			}
		}
		mu.Unlock()

		if !limiter.allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests"})
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
	lastSeen   atomic.Int64
}

func newRateLimiter(maxTokens float64, period time.Duration) *rateLimiter {
	rl := &rateLimiter{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		lastTime:   time.Now(),
		refillRate: maxTokens / period.Seconds(),
	}
	rl.lastSeen.Store(time.Now().UnixNano())
	return rl
}

func (rl *rateLimiter) allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastTime).Seconds()
	rl.tokens = min(rl.maxTokens, rl.tokens+elapsed*rl.refillRate)
	rl.lastTime = now
	rl.lastSeen.Store(now.UnixNano())

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

func main() {
	bind := flag.String("bind", "0.0.0.0", "Address for the web server to listen on (use 127.0.0.1 to restrict to localhost)")
	port := flag.Int("port", 8080, "Port for the web server")
	logPath := flag.String("log", "mysshd.log", "Path to the log file")
	workDir := flag.String("workDir", "./", "Directory for working files and database")
	logLevel := flag.String("level", "debug", "Log level (debug, info, warn, error)")
	webUser := flag.String("user", "admin", "Web admin username (optional)")
	webPass := flag.String("pass", "admin", "Web admin password (optional)")
	flag.Parse()

	// Initialize the myssh logger first
	myssh.InitLogger(*logPath, *logLevel)

	zap.L().Sugar().Infof("%s Starting web server on %s:%d", TAG, *bind, *port)

	StartWebServer(*bind, *port, *logPath, *workDir, *webUser, *webPass)

	wg.Wait()
}
