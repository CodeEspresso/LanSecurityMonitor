# 局域网安全监控系统 (LanSecurityMonitor)

一个轻量级的局域网安全监控系统，用于检测网络中的异常设备、潜在威胁，并通过Bark发送实时通知。

## 功能特性

- [x] 🔍 **网络扫描**：自动扫描局域网内的所有设备
- [x] 🚨 **威胁检测**：检测异常设备、可疑行为
- [x] 🔬 **深度分析**：对可疑设备进行深入分析
- [x] 🔒 **自动隔离**：高风险设备自动限制联网
- [x] 📱 **Bark通知**：实时推送安全警报到手机
- [x] 📊 **历史记录**：保存设备信息和威胁记录
- [x] 🌐 **Web管理界面**：可视化管理和监控
- [x] 🤖 **机器学习**：基于 scikit-learn 的风险评估和行为异常检测

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

# 爱快路由器配置（用于设备封禁）
IKUAI_URL=http://192.168.1.1         # 爱快路由器地址
IKUAI_PORT=80                         # 爱快路由器端口
IKUAI_USERNAME=admin                  # 爱快路由器用户名
IKUAI_PASSWORD=your_password         # 爱快路由器密码

# 自动封禁配置
AUTO_BLOCK_ENABLED=false              # 是否启用自动封禁
AUTO_BLOCK_THRESHOLD=80               # 自动封禁风险阈值（0-100）
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
│   │   ├── device_risk_analyzer.py # 设备风险分析器
│   │   ├── behavior_analyzer.py     # 行为分析器
│   │   ├── bandwidth_monitor.py    # 带宽监控器
│   │   ├── nas_monitor.py          # NAS监控器
│   │   ├── arp_monitor.py          # ARP绑定监控器
│   │   └── __init__.py
│   ├── notifiers/
│   │   ├── bark_notifier.py         # Bark通知
│   │   └── __init__.py
│   └── utils/
│       ├── config.py                # 配置管理
│       ├── logger.py                # 日志工具
│       ├── database.py              # 数据库工具
│       ├── ikuai_api.py            # 爱快路由器API
│       ├── device_utils.py          # 设备工具
│       ├── metrics_exporter.py      # 指标导出
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
- ARP绑定异常（IP-MAC绑定变化、MAC抖动）
- NAS异常访问
- 带宽使用异常

### 3. 设备分析

对可疑设备进行深度分析：
- 流量分析
- 行为分析
- 风险评估
- 隔离建议

### 4. 自动响应

根据威胁等级自动响应：
- **Critical**: 自动隔离设备（需启用自动封禁）
- **High**: 发送紧急通知
- **Medium**: 记录并监控
- **Low**: 仅记录

### 5. ARP绑定监控

实时监控网络ARP表，检测：
- IP-MAC绑定变化（识别ARP欺骗攻击）
- MAC地址抖动（识别MAC随机化攻击）
- 自动封禁高风险设备（需配置爱快路由器）

### 6. ML风险评估

使用机器学习算法增强风险评估：
- Random Forest: 设备风险评分
- Isolation Forest: 行为异常检测

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

- [x] Web管理界面
- [x] 机器学习威胁检测
- [ ] 多种通知方式（邮件、钉钉等）
- [ ] 设备分组管理
- [ ] 流量分析
- [ ] API接口

## 机器学习功能

### 功能说明

系统集成了基于 scikit-learn 的机器学习模块，提供两种智能分析能力：

#### 1. ML 风险增强 (MLRiskEnhancer)
- **算法**: Random Forest 随机森林分类器
- **作用**: 融合多维度特征，智能评估设备风险等级
- **特征**: 厂商评分、设备类型、IP模式、MAC模式、网络角色、端口数量等

#### 2. ML 行为异常检测 (MLBehaviorDetector)
- **算法**: Isolation Forest 孤立森林
- **作用**: 检测设备的异常行为模式
- **特征**: 在线时长方差、连接频率、上线时间段、数据传输率、端口访问模式

### 如何观察 ML 是否在工作

#### 方法1: 查看日志输出

运行系统时关注日志中的以下信息：

```
初始化威胁检测器
已启用设备风险评估功能
已启用ML风险增强功能           # <-- 看到这个说明ML已启用
已启用ML行为异常检测功能        # <-- 看到这个说明行为检测已启用

ML增强风险评估: 设备 192.168.1.100, 分数: 65.5   # <-- 看到这个说明正在做ML增强评估
```

#### 方法2: 查看威胁详情

当检测到威胁时，通知中会包含 ML 增强信息：
- `ml_enhanced: true` - 表示经过 ML 增强
- `confidence` - ML 模型置信度 (0-1)
- `risk_factors` - 风险因素分析

#### 方法3: 模型文件

训练后的模型会保存在：
```
data/ml_models/
├── risk_classifier.pkl      # 风险分类模型
└── behavior_anomaly.pkl     # 行为异常模型
```

#### 方法4: 查看模型信息

系统启动时会输出模型状态：
- 如果显示 "已加载已训练的风险评估模型" → ML 模型已就绪
- 如果显示 "将使用默认规则基础模型" → 训练数据不足，使用规则后备

### 配置参数

```bash
# 机器学习配置
ENABLE_ML_RISK=true              # 启用ML风险增强
ENABLE_ML_BEHAVIOR=true          # 启用ML行为异常检测
ML_MODEL_DIR=data/ml_models      # 模型存储目录
ML_MIN_TRAINING_SAMPLES=50       # 最小训练样本数
ML_BEHAVIOR_MIN_SAMPLES=100      # 行为检测最小样本数
```

### 训练数据要求

ML 模型需要积累一定的历史数据才会真正启用：
- **风险增强**: 需要至少 50 个有标签的设备样本
- **行为异常**: 需要至少 100 条行为记录

在数据不足时，系统会自动使用规则基础的后备方法，保证功能正常运行。

### 让 ML 变得更智能

1. **积累数据**: 正常使用系统越多，ML 模型越准确
2. **反馈纠正**: 在 Web 界面中纠正设备的风险等级，系统会学习你的偏好
3. **定期重训**: 可以手动触发模型重新训练以适应新的威胁模式

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request！
