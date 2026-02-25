#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NAS监控模块
"""

import logging
import subprocess
import re
import socket
import urllib.request
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger('LanSecurityMonitor')


class NASMonitor:
    """NAS监控器"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        # 配置项
        self.enable_nas_monitor = config.get_bool('ENABLE_NAS_MONITOR', True)
        self.nas_devices = config.get_list('NAS_DEVICES', [])
        self.trusted_external_ips = config.get_list('TRUSTED_EXTERNAL_IPS', [])
        self.bandwidth_threshold = config.get_int('BANDWIDTH_THRESHOLD', 1024)
        self.connection_timeout = config.get_int('CONNECTION_TIMEOUT', 10)
        
        # 本机监控配置
        self.enable_self_monitor = config.get_bool('ENABLE_SELF_MONITOR', True)
        self.self_ip = config.get('SELF_IP', '')
        
        # 用户已确认的NAS端口（格式: "IP:端口"）
        self.trusted_nas_ports = config.get_list('TRUSTED_NAS_PORTS', [])
        
        # NAS外网访问监控端口列表（常见NAS远程访问端口）
        self.nas_remote_ports = [
            5000,   # 群晖 DSM web
            5001,   # 群晖 DSM web (SSL)
            8080,   # QNAP / 通用
            8081,   # QNAP (SSL)
            443,    # 通用 HTTPS
            8443,   # 通用 HTTPS
            9000,   # Portainer
            9090,   # Prometheus
            3000,   # Docker UI
        ]
        
        # 高危端口列表（无论内外网都应告警）
        self.dangerous_ports = [
            22,     # SSH
            23,     # Telnet
            3389,   # RDP
            445,    # SMB
            139,    # NetBIOS
            21,     # FTP
            69,     # TFTP
            1433,   # MSSQL
            3306,   # MySQL
            5432,   # PostgreSQL
            27017,  # MongoDB
            6379,   # Redis
            11211,  # Memcached
        ]
        
        # 缓存公网IP（避免频繁请求）
        self._cached_external_ip = None
        self._ip_cache_time = 0
    
    def initialize(self):
        """初始化NAS监控器"""
        if self.enable_nas_monitor:
            self.logger.info("初始化NAS监控器")
            if self.nas_devices:
                self.logger.info(f"监控的NAS设备: {self.nas_devices}")
            if self.trusted_external_ips:
                self.logger.info(f"信任的外部IP: {self.trusted_external_ips}")
        
        if self.enable_self_monitor:
            if not self.self_ip:
                self.self_ip = self._get_local_ip()
            if self.self_ip:
                self.logger.info(f"本机IP: {self.self_ip}")
    
    def _get_local_ip(self) -> str:
        """获取本机IP地址（默认网关所在网段）"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            self.logger.info(f"自动检测到本机IP: {local_ip}")
            return local_ip
        except Exception as e:
            self.logger.error(f"获取本机IP失败: {e}")
            return ''
    
    def _get_external_ip(self) -> str:
        """获取本机外网IP"""
        try:
            external_ip = urllib.request.urlopen('https://api.ipify.org', timeout=5).read().decode('utf-8')
            return external_ip
        except Exception as e:
            self.logger.debug(f"获取外网IP失败: {e}")
            return ''
    
    def monitor_nas_devices(self, current_devices: Dict) -> List[Dict]:
        """监控NAS设备
        
        Args:
            current_devices: 当前设备字典
            
        Returns:
            异常列表
        """
        if not self.enable_nas_monitor:
            return []
        
        self.logger.info("开始监控NAS设备")
        
        anomalies = []
        
        # 查找NAS设备
        nas_devices = []
        for mac, device in current_devices.items():
            # 通过设备类型判断
            if device.get('device_type') == 'nas':
                nas_devices.append(device)
            # 通过配置的MAC地址判断
            elif mac in self.nas_devices:
                nas_devices.append(device)
        
        if not nas_devices:
            self.logger.info("未发现NAS设备")
            return anomalies
        
        for nas_device in nas_devices:
            nas_ip = nas_device.get('ip')
            nas_hostname = nas_device.get('hostname', nas_ip)
            self.logger.info(f"监控NAS设备: {nas_hostname}")
            
            # 检查NAS是否暴露了高危端口
            dangerous_exposed = self._check_exposed_ports(nas_ip, self.dangerous_ports)
            
            if dangerous_exposed:
                # 过滤掉用户已确认的端口
                untrusted_dangerous = []
                externally_accessible = []
                
                for port in dangerous_exposed:
                    trusted_key = f"{nas_ip}:{port}"
                    if trusted_key in self.trusted_nas_ports:
                        self.logger.info(f"端口 {port} 已在信任列表中，跳过告警")
                        continue
                    
                    untrusted_dangerous.append(port)
                    
                    # 检查是否可以从公网访问
                    if self._is_port_externally_accessible(nas_ip, port):
                        externally_accessible.append(port)
                
                # 只对未信任且公网可访问的端口告警
                if externally_accessible:
                    self.logger.warning(f"NAS {nas_hostname} 发现公网可访问的高危端口: {externally_accessible}")
                    anomalies.append({
                        'device': nas_device,
                        'type': 'nas_dangerous_port',
                        'severity': 'high',
                        'description': f"NAS公网可访问高危端口: {', '.join(map(str, externally_accessible))}（建议关闭或限制访问）",
                        'ports': externally_accessible,
                        'action': 'trust_port',
                        'ip': nas_ip
                    })
                elif untrusted_dangerous:
                    # 内网可访问但公网不可访问，仅记录日志
                    self.logger.info(f"NAS {nas_hostname} 内网开放高危端口(公网不可访问): {untrusted_dangerous}")
            
            # 检查NAS是否暴露了远程访问端口（信息告警，非风险）
            remote_exposed = self._check_exposed_ports(nas_ip, self.nas_remote_ports)
            
            if remote_exposed:
                self.logger.info(f"NAS {nas_hostname} 开放远程访问端口: {remote_exposed}")
            
            # 检查带宽使用
            bandwidth_usage = self._check_bandwidth_usage(nas_ip)
            if bandwidth_usage and bandwidth_usage > self.bandwidth_threshold:
                anomalies.append({
                    'device': nas_device,
                    'type': 'high_bandwidth_usage',
                    'severity': 'medium',
                    'description': f"NAS带宽使用异常: {bandwidth_usage} KB/s",
                    'bandwidth': bandwidth_usage
                })
        
        return anomalies
    
    def _check_exposed_ports(self, ip: str, port_list: List[int] = None) -> List[int]:
        """检查NAS是否暴露了指定端口
        
        Args:
            ip: NAS IP地址
            port_list: 要检查的端口列表（默认使用 nas_remote_ports）
            
        Returns:
            暴露的端口列表
        """
        if port_list is None:
            port_list = self.nas_remote_ports
        
        exposed_ports = []
        
        for port in port_list:
            if self._check_port_open(ip, port):
                exposed_ports.append(port)
        
        return exposed_ports
    
    def _check_port_open(self, ip: str, port: int, timeout: float = 1.0) -> bool:
        """检查端口是否开放
        
        Args:
            ip: 目标IP
            port: 端口号
            timeout: 超时时间
            
        Returns:
            端口是否开放
        """
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _is_port_externally_accessible(self, nas_ip: str, port: int) -> bool:
        """检测端口是否可从公网访问
        
        通过对比本地端口和公网IP端口的开放情况来判断。
        如果公网IP:port可连接，说明该端口被映射到了公网。
        
        Args:
            nas_ip: NAS IP地址
            port: 端口号
            
        Returns:
            是否可从公网访问
        """
        import time
        
        # 获取公网IP（带缓存，5分钟有效）
        current_time = time.time()
        if not self._cached_external_ip or (current_time - self._ip_cache_time) > 300:
            self._cached_external_ip = self._get_external_ip()
            self._ip_cache_time = current_time
        
        if not self._cached_external_ip:
            self.logger.warning("无法获取公网IP，跳过公网访问检测")
            return False
        
        # 如果NAS IP就是公网IP，说明有公网IP，直接检测NAS端口
        if nas_ip == self._cached_external_ip:
            return self._check_port_open(nas_ip, port)
        
        # 否则分别检测NAS端口和公网端口
        nas_port_open = self._check_port_open(nas_ip, port)
        if not nas_port_open:
            return False
        
        # 检测公网IP的同端口是否可访问
        external_port_open = self._check_port_open(self._cached_external_ip, port)
        
        return external_port_open
    
    def monitor_self(self) -> List[Dict]:
        """监控本机外网连接
        
        Returns:
            异常列表
        """
        if not self.enable_self_monitor:
            return []
        
        if not self.self_ip:
            self.self_ip = self._get_local_ip()
        
        if not self.self_ip:
            self.logger.warning("无法获取本机IP，跳过本机监控")
            return []
        
        self.logger.info(f"开始监控本机外网连接: {self.self_ip}")
        
        anomalies = []
        
        external_connections = self._check_external_connections(self.self_ip)
        
        for conn in external_connections:
            if not self._is_trusted_connection(conn):
                device_info = {
                    'ip': self.self_ip,
                    'hostname': 'localhost',
                    'mac': '00:00:00:00:00:00',
                    'device_type': 'self'
                }
                anomalies.append({
                    'device': device_info,
                    'type': 'self_untrusted_external_connection',
                    'severity': 'high',
                    'description': f"本机发现非信任外部连接: {conn.get('remote_ip')}:{conn.get('remote_port')}",
                    'connection': conn
                })
        
        if anomalies:
            self.logger.warning(f"本机发现 {len(anomalies)} 个非信任外部连接")
        
        return anomalies
    
    def _check_external_connections(self, ip: str) -> List[Dict]:
        """检查外部连接
        
        Args:
            ip: 设备IP
            
        Returns:
            外部连接列表
        """
        connections = []
        
        try:
            # 使用netstat检查连接
            cmd = f"netstat -ant | grep {ip}:"
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.connection_timeout
            )
            
            # 解析netstat输出
            connections = self._parse_netstat_output(result.stdout, ip)
            
        except Exception as e:
            self.logger.error(f"检查外部连接失败: {str(e)}")
        
        return connections
    
    def _parse_netstat_output(self, output: str, device_ip: str) -> List[Dict]:
        """解析netstat输出"""
        connections = []
        
        lines = output.split('\n')
        for line in lines:
            if line.strip():
                # 示例输出: tcp4       0      0  192.168.1.100.50000    1.2.3.4.80       ESTABLISHED
                parts = line.split()
                if len(parts) >= 5:
                    local_addr = parts[3]
                    remote_addr = parts[4]
                    state = parts[5] if len(parts) > 5 else ''
                    
                    # 检查是否是外部连接
                    if state == 'ESTABLISHED' and remote_addr != '0.0.0.0:*':
                        # 提取IP和端口
                        remote_ip, remote_port = self._parse_address(remote_addr)
                        local_ip, local_port = self._parse_address(local_addr)
                        
                        # 只处理设备的外部连接
                        if local_ip == device_ip and not self._is_internal_ip(remote_ip):
                            connections.append({
                                'local_ip': local_ip,
                                'local_port': local_port,
                                'remote_ip': remote_ip,
                                'remote_port': remote_port,
                                'state': state,
                                'timestamp': datetime.now().isoformat()
                            })
        
        return connections
    
    def _check_bandwidth_usage(self, ip: str) -> Optional[float]:
        """检查带宽使用
        
        Args:
            ip: 设备IP
            
        Returns:
            带宽使用量 (KB/s)
        """
        try:
            # 使用iftop或vnstat检查带宽
            # 这里使用简化的方法，实际应该使用更准确的工具
            cmd = f"iftop -t -s 1 -n | grep {ip}"
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # 解析输出
            # 示例: 192.168.1.100    =>    1.2.3.4       10Kb  20Kb  15Kb
            #                            <=               5Kb   8Kb   6Kb
            output = result.stdout
            if output:
                # 简化处理，实际需要更复杂的解析
                return 0.0
                
        except Exception as e:
            self.logger.error(f"检查带宽使用失败: {str(e)}")
        
        return None
    
    def _is_trusted_connection(self, connection: Dict) -> bool:
        """判断是否是信任的连接
        
        Args:
            connection: 连接信息
            
        Returns:
            是否信任
        """
        remote_ip = connection.get('remote_ip')
        
        # 检查是否在信任列表中
        if remote_ip in self.trusted_external_ips:
            return True
        
        # 检查端口（常见视频流端口）
        remote_port = connection.get('remote_port')
        trusted_ports = ['80', '443', '8080', '8443']  # HTTP/HTTPS端口
        if remote_port in trusted_ports:
            return True
        
        return False
    
    def _is_internal_ip(self, ip: str) -> bool:
        """判断是否是内网IP
        
        Args:
            ip: IP地址
            
        Returns:
            是否是内网IP
        """
        internal_ranges = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[01])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^169\.254\.'
        ]
        
        for pattern in internal_ranges:
            if re.match(pattern, ip):
                return True
        
        return False
    
    def _parse_address(self, addr: str) -> tuple:
        """解析地址
        
        Args:
            addr: 地址字符串 (ip:port)
            
        Returns:
            (ip, port)
        """
        if ':' in addr:
            # 处理IPv4
            if '.' in addr:
                parts = addr.rsplit('.', 1)
                if len(parts) == 2 and ':' in parts[1]:
                    ip_part = parts[0] + '.' + parts[1].split(':')[0]
                    port_part = parts[1].split(':')[1]
                    return ip_part, port_part
            # 处理IPv6
            elif ']' in addr:
                match = re.search(r'\[(.*?)\]:(\d+)', addr)
                if match:
                    return match.group(1), match.group(2)
        
        return addr, ''
    
    def cleanup(self):
        """清理资源"""
        self.logger.info("清理NAS监控器资源")