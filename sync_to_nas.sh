#!/bin/bash
# -*- coding: utf-8 -*-
# 文件同步脚本 - 同步本地文件到NAS

# ==================== 配置参数 ====================

# NAS配置
NAS_HOST="192.168.31.38"
NAS_PORT="10992"
NAS_USER="WangMingzhi"  # 修改为你的NAS用户名
NAS_PATH="/vol2/1000/docker/LanSecurityMonitor"  # 修改为你的NAS目标路径

# 本地路径
LOCAL_PATH="/Volumes/PSSD/项目/LanSecurityMonitor"

# 要排除的文件/目录（空格分隔）
EXCLUDE_FILES=".env config.env __pycache__ *.pyc .git .venv data/*.db data/*.db-journal"

# ==================== 同步选项 ====================

# rsync选项
# -a: 归档模式，保留文件属性
# -v: 详细输出
# -z: 压缩传输
# -P: 显示进度
# --delete: 删除目标目录中不存在于源目录的文件（谨慎使用）
# --exclude: 排除指定文件
RSYNC_OPTIONS="-avzP --progress"

# 是否启用删除模式（true/false）
ENABLE_DELETE=false

# ==================== 函数定义 ====================

# 打印分隔线
print_separator() {
    echo "========================================"
}

# 打印信息
print_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# 打印错误
print_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ❌ 错误: $1" >&2
}

# 打印成功
print_success() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ $1"
}

# 检查rsync是否安装
check_rsync() {
    if ! command -v rsync &> /dev/null; then
        print_error "rsync 未安装"
        print_info "请使用以下命令安装："
        print_info "  macOS: brew install rsync"
        print_info "  Ubuntu/Debian: sudo apt-get install rsync"
        print_info "  CentOS/RHEL: sudo yum install rsync"
        exit 1
    fi
}

# 检查SSH连接
check_ssh_connection() {
    print_info "检查SSH连接..."
    print_info "如果提示输入密码，请输入NAS密码"
    
    if ssh -p "$NAS_PORT" -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$NAS_USER@$NAS_HOST" exit 2>/dev/null; then
        print_success "SSH连接正常"
        return 0
    else
        print_error "SSH连接失败"
        print_info "请检查："
        print_info "  1. NAS地址是否正确: $NAS_HOST:$NAS_PORT"
        print_info "  2. 用户名是否正确: $NAS_USER"
        print_info "  3. 密码是否正确"
        print_info "  4. NAS是否允许SSH连接"
        exit 1
    fi
}

# 构建排除选项
build_exclude_options() {
    local exclude_opts=""
    for item in $EXCLUDE_FILES; do
        exclude_opts="$exclude_opts --exclude='$item'"
    done
    echo "$exclude_opts"
}

# 同步文件
sync_files() {
    local exclude_opts=$(build_exclude_options)
    local rsync_cmd="rsync $RSYNC_OPTIONS $exclude_opts"
    
    if [ "$ENABLE_DELETE" = true ]; then
        rsync_cmd="$rsync_cmd --delete"
    fi
    
    rsync_cmd="$rsync_cmd -e 'ssh -p $NAS_PORT -o StrictHostKeyChecking=no' $LOCAL_PATH/ $NAS_USER@$NAS_HOST:$NAS_PATH/"
    
    print_separator
    print_info "开始同步文件..."
    print_info "源路径: $LOCAL_PATH"
    print_info "目标路径: $NAS_USER@$NAS_HOST:$NAS_PATH"
    print_info "排除文件: $EXCLUDE_FILES"
    if [ "$ENABLE_DELETE" = true ]; then
        print_info "删除模式: 已启用（将删除目标目录中多余的文件）"
    else
        print_info "删除模式: 已禁用"
    fi
    print_info "如果提示输入密码，请输入NAS密码"
    print_separator
    
    # 执行同步
    eval $rsync_cmd
    
    if [ $? -eq 0 ]; then
        print_separator
        print_success "文件同步完成！"
        print_separator
    else
        print_separator
        print_error "文件同步失败！"
        print_separator
        exit 1
    fi
}

# 显示帮助信息
show_help() {
    cat << EOF
文件同步脚本 - 同步本地文件到NAS

用法: $0 [选项]

选项:
    -h, --help          显示此帮助信息
    -d, --delete        启用删除模式（删除目标目录中多余的文件）
    -n, --dry-run       试运行模式（不实际传输文件）
    -c, --check         仅检查SSH连接

配置:
    请在脚本开头修改以下配置项：
    - NAS_HOST: NAS地址
    - NAS_PORT: SSH端口
    - NAS_USER: NAS用户名
    - NAS_PATH: NAS目标路径
    - LOCAL_PATH: 本地路径
    - EXCLUDE_FILES: 要排除的文件/目录

示例:
    $0                  # 普通同步（不删除）
    $0 -d              # 同步并删除目标目录中多余的文件
    $0 -n              # 试运行（查看将要同步的文件）
    $0 -c              # 仅检查SSH连接

注意事项:
    1. 启用删除模式（-d）会删除目标目录中不存在于源目录的文件，请谨慎使用
    2. 建议先使用试运行模式（-n）查看将要同步的文件
    3. .env 和 config.env 文件已被默认排除
    4. 运行时会提示输入NAS密码

EOF
}

# ==================== 主程序 ====================

# 解析命令行参数
ENABLE_DELETE=false
DRY_RUN=false
CHECK_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -d|--delete)
            ENABLE_DELETE=true
            shift
            ;;
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -c|--check)
            CHECK_ONLY=true
            shift
            ;;
        *)
            print_error "未知选项: $1"
            print_info "使用 -h 或 --help 查看帮助信息"
            exit 1
            ;;
    esac
done

# 检查rsync
check_rsync

# 仅检查SSH连接
if [ "$CHECK_ONLY" = true ]; then
    check_ssh_connection
    print_success "SSH连接检查完成"
    exit 0
fi

# 检查SSH连接
check_ssh_connection

# 试运行模式
if [ "$DRY_RUN" = true ]; then
    print_info "试运行模式（不实际传输文件）"
    RSYNC_OPTIONS="$RSYNC_OPTIONS --dry-run"
fi

# 同步文件
sync_files
