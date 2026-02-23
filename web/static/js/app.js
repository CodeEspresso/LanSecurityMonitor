// API请求封装
async function apiRequest(url, options = {}) {
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json'
        },
        credentials: 'same-origin'
    };
    
    const response = await fetch(url, { ...defaultOptions, ...options });
    
    if (response.status === 401) {
        // 未授权，跳转到登录页
        window.location.href = '/login';
        return null;
    }
    
    return await response.json();
}

// 加载用户信息
async function loadUserInfo() {
    try {
        const response = await apiRequest('/api/user/info');
        if (response && response.username) {
            const usernameEl = document.getElementById('username');
            if (usernameEl) {
                usernameEl.textContent = response.username;
            }
        }
    } catch (error) {
        console.error('加载用户信息失败:', error);
    }
}

// 加载仪表盘数据
async function loadDashboard() {
    try {
        // 并行加载所有数据
        const [deviceStats, threatStats, systemStatus, recentThreats] = await Promise.all([
            apiRequest('/api/devices/stats'),
            apiRequest('/api/threats/stats'),
            apiRequest('/api/system/status'),
            apiRequest('/api/threats?per_page=5')
        ]);
        
        // 更新设备统计
        if (deviceStats && deviceStats.success) {
            document.getElementById('total-devices').textContent = deviceStats.stats.total;
            document.getElementById('online-devices').textContent = deviceStats.stats.online;
        }
        
        // 更新威胁统计
        if (threatStats && threatStats.success) {
            const totalThreats = threatStats.stats.total || 0;
            document.getElementById('total-threats').textContent = totalThreats;
        }
        
        // 更新系统状态
        if (systemStatus && systemStatus.success) {
            const status = systemStatus.status;
            
            // 更新学习期状态
            if (status.first_run && status.first_run.is_first_run) {
                document.getElementById('learning-card').style.display = 'block';
                document.getElementById('system-status').textContent = '学习期';
                
                // 更新学习期进度
                updateLearningProgress(status.first_run);
            } else {
                document.getElementById('learning-card').style.display = 'none';
                document.getElementById('system-status').textContent = '正常运行';
            }
        }
        
        // 更新最近威胁
        if (recentThreats && recentThreats.success) {
            updateRecentThreats(recentThreats.threats);
        }
        
    } catch (error) {
        console.error('加载仪表盘数据失败:', error);
    }
}

// 更新学习期进度
function updateLearningProgress(status) {
    if (!status) return;
    
    // 更新时间进度
    const timeProgress = Math.min(100, (status.behavior_time_hours / 24) * 100);
    document.getElementById('behavior-time').textContent = 
        `${status.behavior_time_hours.toFixed(1)}小时`;
    document.getElementById('time-progress').style.width = `${timeProgress}%`;
    
    // 更新设备进度
    const deviceProgress = Math.min(100, (status.devices_with_sufficient_data / status.target_devices) * 100);
    document.getElementById('sufficient-devices').textContent = status.devices_with_sufficient_data;
    document.getElementById('target-devices').textContent = status.target_devices;
    document.getElementById('device-progress').style.width = `${deviceProgress}%`;
}

// 更新最近威胁列表
function updateRecentThreats(threats) {
    const tbody = document.getElementById('recent-threats');
    
    if (!threats || threats.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5" class="text-center text-muted">
                    <div class="empty-state">
                        <i class="bi bi-shield-check"></i>
                        <p>暂无威胁记录</p>
                    </div>
                </td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = threats.map(threat => `
        <tr>
            <td>${formatDateTime(threat.timestamp)}</td>
            <td>${threat.type}</td>
            <td><span class="badge badge-${threat.severity}">${formatSeverity(threat.severity)}</span></td>
            <td>${threat.device_ip || 'N/A'}</td>
            <td>${threat.description || 'N/A'}</td>
        </tr>
    `).join('');
}

// 格式化日期时间
function formatDateTime(dateString) {
    if (!dateString) return 'N/A';
    
    const date = new Date(dateString);
    const now = new Date();
    const diff = now - date;
    
    // 如果是今天
    if (diff < 86400000) {
        return date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
    }
    
    // 如果是昨天
    if (diff < 172800000) {
        return '昨天 ' + date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
    }
    
    // 其他
    return date.toLocaleDateString('zh-CN', { month: '2-digit', day: '2-digit' }) + 
           ' ' + date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
}

// 格式化严重程度
function formatSeverity(severity) {
    const severityMap = {
        'critical': '严重',
        'high': '高',
        'medium': '中',
        'low': '低'
    };
    return severityMap[severity] || severity;
}

// 登出
async function logout() {
    try {
        await apiRequest('/api/logout', { method: 'POST' });
        window.location.href = '/login';
    } catch (error) {
        console.error('登出失败:', error);
    }
}

// 显示通知
function showNotification(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.body.appendChild(alertDiv);
    
    // 3秒后自动关闭
    setTimeout(() => {
        alertDiv.remove();
    }, 3000);
}

// 格式化字节大小
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 格式化持续时间
function formatDuration(seconds) {
    if (seconds < 60) {
        return `${seconds}秒`;
    } else if (seconds < 3600) {
        return `${Math.floor(seconds / 60)}分钟`;
    } else if (seconds < 86400) {
        return `${Math.floor(seconds / 3600)}小时`;
    } else {
        return `${Math.floor(seconds / 86400)}天`;
    }
}
