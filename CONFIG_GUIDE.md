# 局域网安全监控系统 - 配置指南

## 📱 Bark通知配置

### 获取Bark密钥

1. **下载Bark应用**
   - 在iPhone上打开App Store
   - 搜索"Bark"并下载安装

2. **获取密钥**
   - 打开Bark应用
   - 点击右上角的"复制"按钮
   - 密钥会自动复制到剪贴板

3. **配置系统**
   ```bash
   # 编辑配置文件
   vim config/config.env
   
   # 设置Bark密钥
   BARK_KEY=your_copied_key_here
   ```

### Bark配置选项

| 配置项 | 说明 | 推荐值 |
|--------|------|--------|
| `BARK_SERVER` | Bark服务器地址 | `https://api.day.app` |
| `BARK_KEY` | 你的Bark密钥 | 从Bark应用复制 |
| `ENABLE_BARK` | 是否启用通知 | `true` |
| `BARK_ALERT_LEVEL` | 通知级别 | `medium` |
| `NOTIFY_NEW_DEVICE` | 新设备通知 | `true` |
| `NOTIFY_THREAT` | 威胁通知 | `true` |
| `NOTIFY_SMART_HOME_CHANGES` | 智能家居通知 | `false`（减少误报）|
| `SILENT_PERIODS` | 静默时段 | `0-7`（凌晨）|

---

## 🌐 爱快路由器配置

### 获取路由器信息

1. **登录路由器**
   - 浏览器访问 `http://192.168.1.1`
   - 输入用户名和密码登录

2. **确认信息**
   - 确认路由器地址（默认：192.168.1.1）
   - 确认用户名（默认：admin）
   - 记录登录密码

### 配置系统

```bash
# 编辑配置文件
vim config/config.env

# 设置隔离方式
ISOLATION_METHOD=ikuai_router

# 爱快路由器地址
IKUAI_URL=http://192.168.1.1

# 爱快路由器端口
IKUAI_PORT=80

# 爱快路由器用户名
IKUAI_USERNAME=admin

# 爱快路由器密码
IKUAI_PASSWORD=your_password_here
```

### 功能说明

配置完成后，系统将自动：

- ✅ **自动隔离** - 检测到高风险设备时自动添加到路由器黑名单
- ✅ **实时通知** - 隔离成功后立即通过Bark通知你
- ✅ **记录原因** - 在路由器黑名单中记录封禁原因和时间
- ✅ **可手动解除** - 可在路由器管理界面手动解除封禁

### 注意事项

⚠️ **重要提示**：
- 密码会以MD5形式传输到路由器
- 确保路由器密码正确，否则无法登录
- 建议先在测试环境验证API连接
- 如果爱快路由器版本不同，可能需要调整API接口

---

## 🔧 完整配置示例

```bash
# 复制配置文件
cp config/config.env.example config/config.env

# 编辑配置
vim config/config.env
```

### 必须配置项

```bash
# 网络配置
NETWORK_RANGE=192.168.1.0/24

# Bark通知（必须配置）
BARK_KEY=your_bark_key_here

# 爱快路由器（如果需要自动隔离）
ISOLATION_METHOD=ikuai_router
IKUAI_PASSWORD=your_router_password
```

### 可选配置项

```bash
# NAS监控
ENABLE_NAS_MONITOR=true
NAS_DEVICES=00:11:32:AA:BB:CC
TRUSTED_EXTERNAL_IPS=1.2.3.4

# 行为分析
ENABLE_BEHAVIOR_ANALYSIS=true
MIN_OBSERVATIONS=7

# 通知策略
NOTIFY_SMART_HOME_CHANGES=false
SILENT_PERIODS=0-7

# Grafana联动
ENABLE_METRICS=true
METRICS_PORT=9100
```

---

## 🚀 启动系统

### Docker方式（推荐）

```bash
# 构建镜像
docker-compose build

# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f
```

### 直接运行

```bash
# 安装依赖
pip install -r requirements.txt

# 启动系统
python src/main.py
```

---

## 📊 验证配置

### 1. 检查Bark通知

```bash
# 查看日志
tail -f logs/security_monitor.log

# 应该看到类似输出：
# INFO - Bark通知发送成功: 测试通知
```

### 2. 检查爱快路由器连接

```bash
# 查看日志
tail -f logs/security_monitor.log

# 应该看到类似输出：
# INFO - 初始化爱快路由器API: http://192.168.1.1:80
# INFO - 爱快路由器登录成功
```

### 3. 检查Grafana指标

```bash
# 测试指标接口
curl http://localhost:9100/metrics

# 测试API接口
curl http://localhost:9100/api/stats
```

---

## 🛠️ 故障排查

### Bark通知不工作

**问题**：没有收到Bark通知

**解决方法**：
1. 确认BARK_KEY配置正确
2. 检查手机网络连接
3. 查看日志是否有错误信息
4. 尝试手动发送测试通知

### 爱快路由器连接失败

**问题**：无法连接到爱快路由器

**解决方法**：
1. 确认IKUAI_URL配置正确
2. 确认IKUAI_PASSWORD配置正确
3. 检查路由器是否开启API功能
4. 查看爱快路由器日志

### 设备隔离不生效

**问题**：高风险设备没有被隔离

**解决方法**：
1. 确认ISOLATION_METHOD=ikuai_router
2. 检查爱快路由器登录状态
3. 查看日志中的错误信息
4. 手动在路由器管理界面添加黑名单测试

---

## 📞 技术支持

如遇到问题，请提供以下信息：
1. 系统版本
2. 配置文件内容（隐藏敏感信息）
3. 错误日志
4. 路由器型号和版本

---

## 🔒 安全建议

1. **定期更新** - 保持系统和依赖包最新
2. **强密码** - 使用强密码保护路由器和系统
3. **网络隔离** - 将访客网络与主网络隔离
4. **定期检查** - 定期查看Grafana监控面板
5. **备份配置** - 定期备份配置文件和数据库