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
        
        self.enable_port_scan = config.get_bool('ENABLE_PORT_SCAN', False)
        self.port_scan_range = config.get('PORT_SCAN_RANGE', '22,80,443,445,3389,5000,8000,8080,8443')
        self.port_scan_timeout = config.get_int('PORT_SCAN_TIMEOUT', 60)
    
    def initialize(self):
        """初始化扫描器"""
        self.logger.info(f"初始化网络扫描器，监控网段: {self.network_range}")
        if self.enable_port_scan:
            self.logger.info(f"端口扫描已启用，扫描范围: {self.port_scan_range}")
    
    def scan_network(self) -> Dict:
        """扫描网络
        
        Returns:
            Dict: 设备字典 {mac: device_info}
        """
        self.logger.info(f"开始扫描网络: {self.network_range}")
        
        devices = {}
        
        try:
            cmd = f"nmap -sn {self.network_range}"
            
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.scan_timeout
            )
            
            devices = self._parse_nmap_output(result.stdout)
            
            if self.enable_port_scan and devices:
                self.logger.info(f"开始端口扫描，范围: {self.port_scan_range}")
                devices = self._scan_ports_for_devices(devices)
            
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
            enhanced_device = DeviceUtils.analyze_device(device.copy(), self.database)
            enhanced_devices[mac] = enhanced_device
            
            self.logger.debug(f"设备分析结果: {mac} -> {enhanced_device.get('vendor')} ({enhanced_device.get('device_type')})")
        
        return enhanced_devices
    
    def _scan_ports_for_devices(self, devices: Dict) -> Dict:
        """对每个设备进行端口扫描
        
        Args:
            devices: 设备字典
            
        Returns:
            更新后的设备字典，包含端口信息
        """
        for mac, device in devices.items():
            ip = device.get('ip')
            if not ip:
                continue
            
            try:
                ports_info = self._scan_single_host(ip)
                device['open_ports'] = ports_info.get('open_ports', [])
                device['port_details'] = ports_info.get('port_details', [])
                device['port_count'] = len(device['open_ports'])
                
                self.logger.debug(f"设备 {ip} 开放端口: {device['open_ports']}")
                
            except Exception as e:
                self.logger.warning(f"端口扫描失败 {ip}: {str(e)}")
                device['open_ports'] = []
                device['port_details'] = []
                device['port_count'] = 0
        
        return devices
    
    def _scan_single_host(self, ip: str) -> Dict:
        """扫描单个主机的端口
        
        Args:
            ip: 目标IP地址
            
        Returns:
            包含开放端口信息的字典
        """
        ports_info = {
            'open_ports': [],
            'port_details': []
        }
        
        try:
            cmd = f"nmap -sS -p {self.port_scan_range} {ip}"
            
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.port_scan_timeout
            )
            
            ports_info = self._parse_port_output(result.stdout, ip)
            
        except subprocess.TimeoutExpired:
            self.logger.warning(f"端口扫描超时: {ip}")
        except Exception as e:
            self.logger.warning(f"端口扫描异常 {ip}: {str(e)}")
        
        return ports_info
    
    def _parse_port_output(self, output: str, ip: str) -> Dict:
        """解析nmap端口扫描输出
        
        Args:
            output: nmap输出
            ip: 目标IP
            
        Returns:
            端口信息字典
        """
        ports_info = {
            'open_ports': [],
            'port_details': []
        }
        
        lines = output.split('\n')
        for line in lines:
            port_match = re.search(r'(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)', line)
            if port_match:
                port = port_match.group(1)
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4)
                
                if state == 'open':
                    ports_info['open_ports'].append(int(port))
                    ports_info['port_details'].append({
                        'port': int(port),
                        'protocol': protocol,
                        'state': state,
                        'service': service
                    })
        
        return ports_info
    
    def cleanup(self):
        """清理资源"""
        self.logger.info("清理网络扫描器资源")
