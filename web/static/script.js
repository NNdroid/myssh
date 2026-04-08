let lastLogLength = 0;
let isConnected = true;
let autoRefreshInterval;

const statusEl = document.getElementById('status');
const logsEl = document.getElementById('logs');
const clearBtnEl = document.getElementById('clearBtn');
const statsBtnEl = document.getElementById('statsBtn');

document.addEventListener('DOMContentLoaded', function() {
    fetchLogsInitial();
    startAutoRefresh();
});

function updateStatus(connected) {
    isConnected = connected;
    if (connected) {
        statusEl.textContent = '✅ 已连接';
        statusEl.className = 'status connected';
    } else {
        statusEl.textContent = '❌ 连接失败';
        statusEl.className = 'status disconnected';
    }
}

// 首次加载完整日志
function fetchLogsInitial() {
    fetch('/api/v1/log-raw?mode=full')
        .then(response => {
            if (!response.ok) throw new Error('Network error');
            updateStatus(true);
            return response.text();
        })
        .then(text => {
            logsEl.textContent = text;
            lastLogLength = text.length;
            scrollToBottom();
        })
        .catch(err => {
            updateStatus(false);
            console.error("读取日志失败", err);
        });
}

// 增量更新日志
function fetchLogsIncremental() {
    if (!isConnected) return;
    
    fetch('/api/v1/log-raw?mode=incremental')
        .then(response => {
            if (!response.ok) throw new Error('Network error');
            updateStatus(true);
            return response.text();
        })
        .then(text => {
            if (text.length > 0) {
                logsEl.textContent += text;
                lastLogLength += text.length;
                scrollToBottom();
            }
        })
        .catch(err => {
            updateStatus(false);
            console.error("增量更新失败", err);
        });
}

function scrollToBottom() {
    logsEl.scrollTop = logsEl.scrollHeight;
}

function startAutoRefresh() {
    // 每 2 秒检查一次新日志
    autoRefreshInterval = setInterval(fetchLogsIncremental, 2000);
}

function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
    }
}

function clearLogs() {
    if (confirm('确定要清空日志吗？')) {
        fetch('/api/v1/log-clear', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.message) {
                logsEl.textContent = '日志已清空';
                lastLogLength = 0;
                updateStatus(true);
            }
        })
        .catch(err => {
            alert('清空日志失败: ' + err);
            updateStatus(false);
        });
    }
}

function showStats() {
    fetch('/api/v1/log-stats')
        .then(response => response.json())
        .then(data => {
            const modal = document.createElement('div');
            modal.className = 'modal';
            modal.innerHTML = `
                <div class="modal-content">
                    <span class="close" onclick="this.parentElement.parentElement.style.display='none'">&times;</span>
                    <h2>日志统计信息</h2>
                    <p><strong>文件大小:</strong> ${formatBytes(data.file_size)}</p>
                    <p><strong>行数:</strong> ${data.line_count}</p>
                    <p><strong>最后修改:</strong> ${new Date(data.last_modified).toLocaleString()}</p>
                    <button onclick="this.parentElement.parentElement.style.display='none'">关闭</button>
                </div>
            `;
            document.body.appendChild(modal);
            modal.style.display = 'block';
            modal.addEventListener('click', function(e) {
                if (e.target === modal) {
                    modal.style.display = 'none';
                }
            });
        })
        .catch(err => {
            alert('获取统计信息失败: ' + err);
            updateStatus(false);
        });
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// 页面关闭时停止自动刷新
window.addEventListener('beforeunload', function() {
    stopAutoRefresh();
});