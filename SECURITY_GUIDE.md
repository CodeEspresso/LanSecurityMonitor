# 局域网安全监控系统 - 安全配置指南

## 🔒 为什么需要安全配置？

你说得对！配置文件中明文存储密码和密钥存在严重安全风险：

- ❌ **容易被窃取** - 配置文件可能被意外分享或上传到代码仓库
- ❌ **权限问题** - 配置文件可能被其他用户读取
- ❌ **日志泄露** - 密码可能被记录到日志中
- ❌ **黑客目标** - 配置文件是黑客最喜欢的目标之一

## ✅ 安全配置方案

系统提供了三种安全配置方式：

### 方案1: 环境变量（推荐）

#### Docker Compose方式

```bash
# 1. 复制示例文件
cp .env.example .env

# 2. 编辑 .env 文件
vim .env

# 填写敏感信息：
BARK_KEY=your_bark_key_here
IKUAI_PASSWORD=your_router_password

# 3. 启动服务
docker-compose up -d
```

#### 直接运行方式

```bash
# 1. 设置环境变量
export BARK_KEY=your_bark_key_here
export IKUAI_PASSWORD=your_router_password

# 2. 启动系统
python src/main.py
```

#### 永久设置环境变量

```bash
# 添加到 ~/.bashrc 或 ~/.zshrc
echo 'export BARK_KEY=your_bark_key_here' >> ~/.bashrc
echo 'export IKUAI_PASSWORD=your_router_password' >> ~/.bashrc

# 重新加载配置
source ~/.bashrc
```

### 方案2: .env 文件（Docker推荐）

```bash
# 1. 复制示例文件
cp .env.example .env

# 2. 编辑 .env 文件
vim .env

# 填写敏感信息
BARK_KEY=your_bark_key_here
IKUAI_PASSWORD=your_router_password

# 3. 启动服务
docker-compose up -d
```

### 方案3: Docker Secrets（生产环境推荐）

```yaml
# docker-compose.yml
services:
  lan-security-monitor:
    secrets:
      - bark_key
      - ikuai_password

secrets:
  bark_key:
    file: ./secrets/bark_key.txt
  ikuai_password:
    file: ./secrets/ikuai_password.txt
```

## 📋 安全配置检查

系统启动时会自动检查安全配置，并显示安全等级：

### 高安全等级 ✅

```
============================================================
安全配置检查
============================================================
✅ 安全等级: 高 - 所有敏感配置都通过环境变量配置
============================================================
```

### 中安全等级 ⚠️

```
============================================================
安全配置检查
============================================================
⚠️  安全等级: 中 - 部分敏感配置在配置文件中
   建议迁移到环境变量: ['IKUAI_PASSWORD']
============================================================
```

### 低安全等级 ❌

```
============================================================
安全配置检查
============================================================
❌ 安全等级: 低 - 敏感配置在配置文件中明文存储
   存在风险的配置: ['BARK_KEY', 'IKUAI_PASSWORD']
   强烈建议使用环境变量存储敏感信息！
============================================================
```

## 🔐 敏感配置列表

| 配置项 | 说明 | 推荐存储方式 |
|--------|------|--------------|
| `BARK_KEY` | Bark通知密钥 | 环境变量 |
| `IKUAI_PASSWORD` | 爱快路由器密码 | 环境变量 |
| `DB_PASSWORD` | 数据库密码 | 环境变量 |
| `ROUTER_PASSWORD` | 路由器密码 | 环境变量 |

## 🚀 快速配置步骤

### Docker方式

```bash
# 1. 复制配置文件
cp config/config.env.example config/config.env
cp .env.example .env

# 2. 编辑 .env 文件（敏感信息）
vim .env
# 填写：
# BARK_KEY=your_bark_key_here
# IKUAI_PASSWORD=your_router_password

# 3. 编辑 config/config.env（非敏感配置）
vim config/config.env
# 配置网络范围、监控间隔等

# 4. 启动服务
docker-compose up -d

# 5. 查看日志
docker-compose logs -f
```

### 直接运行方式

```bash
# 1. 复制配置文件
cp config/config.env.example config/config.env

# 2. 编辑配置文件（非敏感信息）
vim config/config.env

# 3. 设置环境变量（敏感信息）
export BARK_KEY=your_bark_key_here
export IKUAI_PASSWORD=your_router_password

# 4. 启动系统
python src/main.py
```

## 🛡️ 安全最佳实践

### 1. 文件权限

```bash
# 设置 .env 文件权限为仅所有者可读写
chmod 600 .env

# 设置配置文件权限为仅所有者可读写
chmod 600 config/config.env
```

### 2. 版本控制

```bash
# 确保 .gitignore 包含以下内容
cat .gitignore
# 应该包含：
# config/config.env
# *.env
# !.env.example
```

### 3. 日志管理

```bash
# 确保日志目录权限正确
chmod 700 logs/

# 定期清理日志
find logs/ -name "*.log" -mtime +30 -delete
```

### 4. 定期更换密钥

- 定期更换Bark密钥
- 定期更换路由器密码
- 定期更换数据库密码

### 5. 监控异常

- 监控配置文件的访问日志
- 监控环境变量的变化
- 定期检查安全配置状态

## 🔍 故障排查

### 问题1: 环境变量未生效

**症状**：系统提示"密钥未配置"

**解决方法**：
```bash
# 检查环境变量
echo $BARK_KEY
echo $IKUAI_PASSWORD

# 如果为空，重新设置
export BARK_KEY=your_key_here
export IKUAI_PASSWORD=your_password

# 或在 .env 文件中设置
vim .env
```

### 问题2: Docker Compose环境变量未生效

**症状**：Docker容器中环境变量为空

**解决方法**：
```bash
# 检查 .env 文件是否存在
ls -la .env

# 检查 .env 文件格式
cat .env

# 重新构建并启动
docker-compose down
docker-compose up -d --build

# 检查容器环境变量
docker exec lan-security-monitor env | grep -E 'BARK_KEY|IKUAI_PASSWORD'
```

### 问题3: 安全等级显示为低

**症状**：系统提示"安全等级: 低"

**解决方法**：
```bash
# 检查配置文件中是否有敏感信息
grep -E 'BARK_KEY|IKUAI_PASSWORD|DB_PASSWORD' config/config.env

# 如果有，删除这些行
vim config/config.env

# 改用环境变量设置
export BARK_KEY=your_key_here
export IKUAI_PASSWORD=your_password
```

## 📞 技术支持

如果遇到安全问题，请：
1. 不要在公开渠道分享敏感信息
2. 使用占位符代替真实密码
3. 提供完整的错误日志
4. 说明你的配置方式（Docker/直接运行）

## 🎯 总结

| 方式 | 安全性 | 易用性 | 推荐场景 |
|------|--------|--------|----------|
| 环境变量 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | 开发/测试 |
| .env 文件 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Docker部署 |
| Docker Secrets | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | 生产环境 |

**记住：永远不要在配置文件中明文存储密码和密钥！**