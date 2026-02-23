#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络扫描器模块
"""

import logging
import subprocess
import re
from typing import Dict, List
from datetime import datetime

from ..utils.device_utils import DeviceUtils


class NetworkScanner:
    """网络扫描器"""
    
    def __init__(self, config, database=None):
        self.config = config
        self.database = database
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        self.network_range = config.get('NETWORK_RANGE', '192.168.1.0/24')
        self.scan_timeout = config.get_int('SCAN_TIMEOUT', 30)
    
    def initialize(self):
        """初始化扫描器"""
        self.logger.info(f"初始化网络扫描器，监控网段: {self.network_range}")
    
    def scan_network(self) -> Dict:
        """扫描网络
        
        Returns:
            Dict: 设备字典 {mac: device_info}
        """
        self.logger.info(f"开始扫描网络: {self.network_range}")
        
        devices = {}
        
        try:
            # 使用nmap扫描
            # -sn: Ping扫描，不进行端口扫描
            # -n: 不进行DNS解析
            cmd = f"nmap -sn {self.network_range}"
            
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.scan_timeout
            )
            
            # 解析nmap输出
            devices = self._parse_nmap_output(result.stdout)
            
            # 增强设备信息
            devices = self._enhance_device_info(devices)
            
            self.logger.info(f"扫描完成，发现 {len(devices)} 个设备")
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"网络扫描超时（{self.scan_timeout}秒）")
        except Exception as e:
            self.logger.error(f"网络扫描失败: {str(e)}", exc_info=True)
        
        return devices
    
    def _parse_nmap_output(self, output: str) -> Dict:
        """解析nmap输出"""
        devices = {}
        
        lines = output.split('\n')
        current_ip = None
        
        for line in lines:
            # 提取IP地址
            ip_match = re.search(r'Nmap scan report for .*?(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                current_ip = ip_match.group(1)
            
            # 提取MAC地址
            mac_match = re.search(r'MAC Address: ([0-9A-Fa-f:]{17})', line)
            if mac_match and current_ip:
                mac = mac_match.group(1).lower()
                
                # 提取厂商信息
                vendor = ''
                vendor_match = re.search(r'MAC Address: .*? \((.*?)\)', line)
                if vendor_match:
                    vendor = vendor_match.group(1)
                
                devices[mac] = {
                    'mac': mac,
                    'ip': current_ip,
                    'hostname': 'Unknown',
                    'vendor': vendor,
                    'os_type': 'Unknown',
                    'first_seen': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat(),
                    'is_known': False
                }
                
                current_ip = None
        
        return devices
    
    def _enhance_device_info(self, devices: Dict) -> Dict:
        """增强设备信息"""
        enhanced_devices = {}
        
        for mac, device in devices.items():
            # 使用设备工具分析设备（传入database以支持用户标记的设备和主机名）
            enhanced_device = DeviceUtils.analyze_device(device.copy(), self.database)
            enhanced_devices[mac] = enhanced_device
            
            # 记录设备信息
            self.logger.debug(f"设备分析结果: {mac} -> {enhanced_device.get('vendor')} ({enhanced_device.get('device_type')})")
        
        return enhanced_devices
    
    def cleanup(self):
        """清理资源"""
        self.logger.info("清理网络扫描器资源")
