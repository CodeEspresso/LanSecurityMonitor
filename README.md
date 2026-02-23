# 局域网安全监控系统 (LanSecurityMonitor)

一个轻量级的局域网安全监控系统，用于检测网络中的异常设备、潜在威胁，并通过Bark发送实时通知。

## 功能特性

- 🔍 **网络扫描**：自动扫描局域网内的所有设备
- 🚨 **威胁检测**：检测异常设备、可疑行为
- 🔬 **深度分析**：对可疑设备进行深入分析
- 🔒 **自动隔离**：高风险设备自动限制联网
- 📱 **Bark通知**：实时推送安全警报到手机
- 📊 **历史记录**：保存设备信息和威胁记录
- 🌐 **Web管理界面**：可视化管理和监控（新增）

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置文件

复制配置模板：
```bash
cp config/config.env.example config/config.env
```

编辑配置文件：
```bash
vi config/config.env
```

### 3. 运行监控

```bash
python src/main.py
```

### 4. Docker运行

```bash
docker compose up -d
```

### 5. 访问Web界面

```
URL: http://localhost:5001
默认账号: admin
默认密码: admin123
```

## 配置说明

### 必需配置

```bash
# 网络配置
NETWORK_RANGE=192.168.1.0/24          # 监控的网段
GATEWAY_IP=192.168.1.1                # 网关IP

# Bark通知配置
BARK_SERVER=https://api.day.app       # Bark服务器地址
BARK_KEY=your_bark_key                # Bark密钥
```

### 可选配置

```bash
# 监控配置
CHECK_INTERVAL=300                    # 检查间隔（秒）
LOG_LEVEL=INFO                        # 日志级别

# 威胁检测配置
ENABLE_AUTO_ISOLATE=true              # 是否自动隔离高风险设备
ALERT_THRESHOLD=medium                # 告警阈值（low/medium/high/critical）
```

## 项目结构

```
LanSecurityMonitor/
├── src/
│   ├── main.py                      # 主入口
│   ├── core/
│   │   ├── security_monitor.py      # 安全监控核心
│   │   └── __init__.py
│   ├── monitors/
│   │   ├── network_scanner.py       # 网络扫描器
│   │   ├── threat_detector.py       # 威胁检测器
│   │   ├── device_analyzer.py       # 设备分析器
│   │   └── __init__.py
│   ├── notifiers/
│   │   ├── bark_notifier.py         # Bark通知
│   │   └── __init__.py
│   └── utils/
│       ├── config.py                # 配置管理
│       ├── logger.py                # 日志工具
│       ├── database.py              # 数据库工具
│       └── __init__.py
├── config/
│   └── config.env.example           # 配置模板
├── data/                            # 数据目录
├── logs/                            # 日志目录
├── Dockerfile                       # Docker配置
├── docker-compose.yml               # Docker Compose配置
├── requirements.txt                 # Python依赖
└── README.md                        # 说明文档
```

## 核心功能

### 1. 网络扫描

使用nmap和scapy扫描局域网，获取：
- 设备IP地址
- MAC地址
- 主机名
- 操作系统类型
- 开放端口

### 2. 威胁检测

检测以下威胁：
- 未知设备接入
- 异常端口开放
- 可疑网络行为
- 设备指纹异常

### 3. 设备分析

对可疑设备进行深度分析：
- 流量分析
- 行为分析
- 风险评估
- 隔离建议

### 4. 自动响应

根据威胁等级自动响应：
- **Critical**: 自动隔离设备
- **High**: 发送紧急通知
- **Medium**: 记录并监控
- **Low**: 仅记录

## Bark通知配置

### 获取Bark Key

1. 在iPhone上下载Bark应用
2. 打开应用，复制你的Key
3. 在配置文件中设置`BARK_KEY`

### 自定义Bark服务器

如果你使用自建Bark服务器：
```bash
BARK_SERVER=https://your-server.com
```

## Docker部署

### 构建镜像

```bash
docker build -t lan-security-monitor .
```

### 运行容器

```bash
docker run -d \
  --name lan-monitor \
  --network host \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  lan-security-monitor
```

### 使用Docker Compose

```bash
docker compose up -d
```

## 注意事项

1. **网络权限**：需要root权限或CAP_NET_RAW能力进行网络扫描
2. **网络模式**：Docker运行时建议使用host网络模式
3. **性能影响**：频繁扫描可能影响网络性能，建议间隔不低于60秒
4. **隐私合规**：请确保遵守当地法律法规，仅监控自己的网络

## 开发计划

- [ ] Web管理界面
- [ ] 机器学习威胁检测
- [ ] 多种通知方式（邮件、钉钉等）
- [ ] 设备分组管理
- [ ] 流量分析
- [ ] API接口

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request！
