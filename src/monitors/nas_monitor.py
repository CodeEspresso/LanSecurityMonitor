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
            self.logger.info(f"监控NAS设备: {nas_device.get('hostname', nas_device.get('ip'))}")
            
            # 检查外网连接
            external_connections = self._check_external_connections(nas_device.get('ip'))
            
            for conn in external_connections:
                if not self._is_trusted_connection(conn):
                    anomalies.append({
                        'device': nas_device,
                        'type': 'untrusted_external_connection',
                        'severity': 'high',
                        'description': f"发现非信任外部连接: {conn.get('remote_ip')}:{conn.get('remote_port')}",
                        'connection': conn
                    })
            
            # 检查带宽使用
            bandwidth_usage = self._check_bandwidth_usage(nas_device.get('ip'))
            if bandwidth_usage and bandwidth_usage > self.bandwidth_threshold:
                anomalies.append({
                    'device': nas_device,
                    'type': 'high_bandwidth_usage',
                    'severity': 'medium',
                    'description': f"NAS带宽使用异常: {bandwidth_usage} KB/s",
                    'bandwidth': bandwidth_usage
                })
        
        return anomalies
    
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