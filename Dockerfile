FROM python:3.10-slim

LABEL maintainer="LanSecurityMonitor"
LABEL description="局域网安全监控系统"

# 使用阿里云镜像源加速
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    nmap \
    tcpdump \
    net-tools \
    iputils-ping \
    iproute2 \
    iptables \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 复制依赖文件
COPY requirements.txt .

# 安装Python依赖（使用清华镜像源加速）
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

# 复制应用代码
COPY src/ ./src/
COPY config/ ./config/
COPY web/ ./web/

# 创建必要的目录
RUN mkdir -p logs data

# 设置环境变量
ENV PYTHONUNBUFFERED=1
ENV CONFIG_FILE=/app/config/config.env

# 健康检查
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD pgrep -f "python.*main.py" || exit 1

# 启动命令
CMD ["python", "-u", "src/main.py"]
