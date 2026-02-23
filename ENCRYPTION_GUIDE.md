# 局域网安全监控系统 - 配置文件加密指南

## 🔒 为什么需要加密配置文件？

虽然使用环境变量存储敏感信息已经很安全，但在某些情况下，你可能希望：

- ✅ **完全加密** - 配置文件本身完全加密，即使被窃取也无法读取
- ✅ **统一管理** - 所有配置（包括非敏感信息）都在一个加密文件中
- ✅ **版本控制** - 可以安全地备份和迁移加密配置文件
- ✅ **防篡改** - 加密文件被修改后会无法解密，防止被恶意篡改

## 🚀 加密配置文件使用方法

### 步骤1: 准备加密密码

```bash
# 设置加密密码环境变量
export CONFIG_ENCRYPT_PASSWORD=your_secure_password

# 或者在 .env 文件中设置
# CONFIG_ENCRYPT_PASSWORD=your_secure_password
```

### 步骤2: 创建原始配置文件

```bash
# 复制配置文件
cp config/config.env.example config/config.env.clear

# 编辑原始配置（包含所有配置，包括敏感信息）
vim config/config.env.clear

# 示例配置内容：
NETWORK_RANGE=192.168.1.0/24
CHECK_INTERVAL=300
ENABLE_BARK=true
BARK_KEY=your_bark_key_here
IKUAI_PASSWORD=your_router_password
```

### 步骤3: 加密配置文件

```bash
# 使用加密工具
python src/utils/config_encrypt.py encrypt \
    --input config/config.env.clear \
    --output config/config.env

# 或者使用环境变量
CONFIG_ENCRYPT_PASSWORD=your_secure_password python src/utils/config_encrypt.py encrypt \
    --input config/config.env.clear \
    --output config/config.env
```

### 步骤4: 验证加密文件

```bash
# 查看加密后的文件（应该是乱码）
cat config/config.env

# 验证文件大小ls -la config/config.env
```

### 步骤5: 清理临时文件

```bash
# 删除原始明文配置文件
rm config/config.env.clear

# 确保文件权限安全
chmod 600 config/config.env
```

### 步骤6: 启动系统

#### **Docker方式**

```bash
# 1. 在 .env 文件中设置加密密码
vim .env
# 添加：
# CONFIG_ENCRYPT_PASSWORD=your_secure_password

# 2. 启动服务
docker-compose up -d

# 3. 查看日志
docker-compose logs -f
# 应该看到："初始化配置文件加密器"
# 应该看到："加载加密配置文件: /app/config/config.env"
```

#### **直接运行方式**

```bash
# 1. 设置环境变量
export CONFIG_ENCRYPT_PASSWORD=your_secure_password

# 2. 启动系统
python src/main.py

# 应该看到："初始化配置文件加密器"
# 应该看到："加载加密配置文件: config/config.env"
```

---

## 📋 完整流程示例

### **Docker部署完整流程**

```bash
# 1. 复制配置文件
cp config/config.env.example config/config.env.clear
cp .env.example .env

# 2. 编辑原始配置（包含所有配置）
vim config/config.env.clear

# 3. 编辑 .env 文件（设置密码）
vim .env
# 添加：
# CONFIG_ENCRYPT_PASSWORD=your_secure_password

# 4. 加密配置文件
CONFIG_ENCRYPT_PASSWORD=your_secure_password python src/utils/config_encrypt.py encrypt \
    --input config/config.env.clear \
    --output config/config.env

# 5. 清理临时文件
rm config/config.env.clear
chmod 600 config/config.env

# 6. 启动服务
docker-compose up -d

# 7. 查看日志
docker-compose logs -f
```

### **直接运行完整流程**

```bash
# 1. 复制配置文件
cp config/config.env.example config/config.env.clear

# 2. 编辑原始配置（包含所有配置）
vim config/config.env.clear

# 3. 设置加密密码
export CONFIG_ENCRYPT_PASSWORD=your_secure_password

# 4. 加密配置文件
python src/utils/config_encrypt.py encrypt \
    --input config/config.env.clear \
    --output config/config.env

# 5. 清理临时文件
rm config/config.env.clear
chmod 600 config/config.env

# 6. 启动系统
python src/main.py
```

---

## 🔍 解密配置文件（需要时）

### 解密查看或修改

```bash
# 解密配置文件
python src/utils/config_encrypt.py decrypt \
    --input config/config.env \
    --output config/config.env.decrypted

# 查看解密后的内容
cat config/config.env.decrypted

# 修改后重新加密
python src/utils/config_encrypt.py encrypt \
    --input config/config.env.decrypted \
    --output config/config.env

# 清理临时文件
rm config/config.env.decrypted
```

### 批量解密

```bash
# 批量解密所有配置文件
CONFIG_ENCRYPT_PASSWORD=your_secure_password python src/utils/config_encrypt.py decrypt \
    --input config/config.env \
    --output config/config.env.decrypted
```

---

## ⚠️ 注意事项

### **重要提示**

1. **密码安全**
   - 加密密码必须妥善保管，丢失后无法恢复配置
   - 建议使用强密码（至少12位，包含字母、数字、符号）
   - 可以使用密码管理器存储加密密码

2. **备份**
   - 定期备份加密配置文件和加密密码
   - 建议将备份存储在安全的地方（如加密U盘）

3. **权限**
   - 确保加密文件权限为 600（仅所有者可读写）
   - 确保 .env 文件权限为 600

4. **迁移**
   - 迁移到新系统时，需要同时迁移：
     - 加密配置文件 `config/config.env`
     - 加密密码 `CONFIG_ENCRYPT_PASSWORD`

5. **兼容性**
   - 系统会自动检测配置文件是否加密
   - 如果未设置加密密码，会使用明文配置
   - 支持从加密配置切换到明文配置，反之亦然

---

## 🛠️ 故障排查

### 问题1: 加密失败

**症状**：`❌ 加密失败`

**解决方法**：
```bash
# 检查输入文件是否存在
ls -la config/config.env.clear

# 检查加密密码是否设置
echo $CONFIG_ENCRYPT_PASSWORD

# 检查文件权限
chmod 644 config/config.env.clear

# 查看详细错误
CONFIG_ENCRYPT_PASSWORD=your_password python src/utils/config_encrypt.py encrypt \
    --input config/config.env.clear \
    --output config/config.env
```

### 问题2: 解密失败

**症状**：`❌ 解密失败`

**解决方法**：
```bash
# 检查加密密码是否正确
CONFIG_ENCRYPT_PASSWORD=your_password python src/utils/config_encrypt.py decrypt \
    --input config/config.env \
    --output config/config.env.decrypted

# 检查文件是否损坏
ls -la config/config.env

# 尝试使用备份文件
cp config/config.env.bak config/config.env
```

### 问题3: 系统启动失败

**症状**：`加载配置文件失败`

**解决方法**：
```bash
# 检查加密密码是否设置
# Docker方式：检查 .env 文件
# 直接运行：检查环境变量

# 检查配置文件是否存在
ls -la config/config.env

# 验证文件是否可解密
CONFIG_ENCRYPT_PASSWORD=your_password python src/utils/config_encrypt.py decrypt \
    --input config/config.env \
    --output config/config.env.test

# 如果解密失败，使用备份或重新创建
```

### 问题4: 性能问题

**症状**：系统启动变慢

**解决方法**：
- 加密解密过程会增加少量启动时间（通常 < 1秒）
- 运行时性能不受影响，因为配置只在启动时加载
- 如果性能问题严重，可以考虑使用明文配置

---

## 📊 安全级别对比

| 配置方式 | 安全性 | 易用性 | 性能 | 推荐场景 |
|----------|--------|--------|------|----------|
| 明文配置 | ❌ 低 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 开发/测试 |
| 环境变量 | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 生产环境 |
| 加密文件 | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐ | 高安全需求 |
| 环境变量 + 加密文件 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | 最高安全级别 |

---

## 🎯 最佳实践推荐

### **推荐配置方案**

| 级别 | 配置方式 | 适用场景 |
|------|----------|----------|
| **基础安全** | 明文配置 + 环境变量 | 个人开发环境 |
| **标准安全** | 环境变量 | 家庭使用 |
| **高级安全** | 加密配置文件 | 企业环境 |
| **最高安全** | 环境变量 + 加密配置文件 | 敏感环境 |

### **企业级安全配置**

```bash
# 1. 使用加密配置文件存储所有配置
python src/utils/config_encrypt.py encrypt \
    --input config/config.env.clear \
    --output config/config.env

# 2. 使用环境变量存储最敏感信息
export CONFIG_ENCRYPT_PASSWORD=your_secure_password
export BARK_KEY=your_bark_key
export IKUAI_PASSWORD=your_router_password

# 3. 启动系统
python src/main.py

# 4. 监控配置文件访问
# 可以添加文件访问审计
```

---

## 📞 技术支持

如果遇到加密相关问题，请提供：
1. 完整的错误日志
2. 加密工具输出
3. 文件权限信息
4. 操作系统版本

---

## 🎉 总结

**配置文件加密功能** 为你的系统提供了额外的安全保障：

- ✅ **完全加密** - 配置文件完全加密，即使被窃取也无法读取
- ✅ **自动检测** - 系统会自动检测配置文件是否加密
- ✅ **无缝切换** - 支持在明文和加密配置之间无缝切换
- ✅ **性能友好** - 只在启动时进行加密解密，运行时无影响
- ✅ **向后兼容** - 不影响现有明文配置的使用

现在你可以根据自己的安全需求选择最适合的配置方式了！