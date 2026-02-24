#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARP监控模块 - 检测IP-MAC绑定变化，识别ARP欺骗攻击
"""

import logging
import subprocess
import re
from typing import Dict, List, Optional, Set
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger('LanSecurityMonitor')


class ARPTable:
    """ARP表条目"""
    def __init__(self, ip: str, mac: str, device_type: str = 'unknown'):
        self.ip = ip
        self.mac = mac.upper()
        self.device_type = device_type
        self.timestamp = datetime.now()
    
    def __repr__(self):
        return f"ARPTable(ip={self.ip}, mac={self.mac}, type={self.device_type})"


class ARPMonitor:
    """ARP监控器 - 检测IP-MAC绑定异常"""
    
    def __init__(self, config, database=None):
        self.config = config
        self.database = database
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        self.arp_table: Dict[str, ARPTable] = {}
        self.mac_history: Dict[str, List[str]] = defaultdict(list)
        self.ip_history: Dict[str, List[str]] = defaultdict(list)
        
        self.max_mac_history = 10
        self.max_ip_history = 10
    
    def initialize(self):
        """初始化ARP监控"""
        self.logger.info("初始化ARP监控器")
        self.refresh_arp_table()
    
    def refresh_arp_table(self) -> Dict[str, ARPTable]:
        """刷新ARP表
        
        Returns:
            Dict: ARP表 {ip: ARPTable}
        """
        self.arp_table = {}
        
        try:
            result = subprocess.run(
                ['arp', '-a'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                self._parse_arp_output(result.stdout)
            else:
                self._parse_proc_net_arp()
                
        except FileNotFoundError:
            self._parse_proc_net_arp()
        except Exception as e:
            self.logger.error(f"读取ARP表失败: {str(e)}")
        
        return self.arp_table
    
    def _parse_arp_output(self, output: str) -> None:
        """解析 arp -a 输出"""
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
            mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
            
            if ip_match and mac_match:
                ip = ip_match.group(1)
                mac = mac_match.group(0).replace('-', ':').upper()
                
                if mac != '00:00:00:00:00:00' and not mac.startswith('FF:FF'):
                    self.arp_table[ip] = ARPTable(ip, mac)
                    self._update_history(ip, mac)
    
    def _parse_proc_net_arp(self) -> None:
        """解析 /proc/net/arp"""
        try:
            with open('/proc/net/arp', 'r') as f:
                for line in f:
                    if line.startswith('IP'):
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3].upper()
                        
                        if mac != '00:00:00:00:00:00' and not mac.startswith('FF:FF'):
                            self.arp_table[ip] = ARPTable(ip, mac)
                            self._update_history(ip, mac)
                            
        except Exception as e:
            self.logger.error(f"解析/proc/net/arp失败: {str(e)}")
    
    def _update_history(self, ip: str, mac: str) -> None:
        """更新历史记录"""
        if mac not in self.mac_history[ip]:
            self.mac_history[ip].append(mac)
            if len(self.mac_history[ip]) > self.max_mac_history:
                self.mac_history[ip].pop(0)
        
        if ip not in self.ip_history[mac]:
            self.ip_history[mac].append(ip)
            if len(self.ip_history[mac]) > self.max_ip_history:
                self.ip_history[mac].pop(0)
    
    def check_binding_changes(self, device_ip: str, device_mac: str) -> Dict:
        """检查设备的IP-MAC绑定是否变化
        
        Args:
            device_ip: 设备IP地址
            device_mac: 设备MAC地址
            
        Returns:
            Dict: 绑定检测结果
        """
        result = {
            'is_normal': True,
            'anomaly_type': None,
            'details': '',
            'risk_score': 0
        }
        
        current_mac = device_mac.upper()
        
        if device_ip in self.mac_history:
            known_macs = self.mac_history[device_ip]
            
            if current_mac not in known_macs and len(known_macs) > 0:
                result['is_normal'] = False
                result['anomaly_type'] = 'ip_mac_mismatch'
                result['details'] = f"IP {device_ip} 的MAC从 {known_macs[-1]} 变为 {current_mac}"
                result['risk_score'] = 80
                result['previous_mac'] = known_macs[-1]
                result['current_mac'] = current_mac
        
        if current_mac in self.ip_history:
            known_ips = self.ip_history[current_mac]
            
            if device_ip not in known_ips and len(known_ips) > 0:
                result['is_normal'] = False
                result['anomaly_type'] = 'mac_ip_mismatch'
                existing_ip = known_ips[-1]
                if result['anomaly_type'] != 'ip_mac_mismatch':
                    result['details'] = f"MAC {current_mac} 的IP从 {existing_ip} 变为 {device_ip}"
                    result['risk_score'] = max(result['risk_score'], 70)
                result['previous_ip'] = existing_ip
                result['current_ip'] = device_ip
        
        return result
    
    def detect_mac_flapping(self, mac: str, time_window: int = 60) -> Dict:
        """检测MAC地址抖动（短时间内MAC频繁变化）
        
        Args:
            mac: MAC地址
            time_window: 时间窗口（秒），暂未实现
            
        Returns:
            Dict: 抖动检测结果
        """
        result = {
            'is_flapping': False,
            'change_count': 0,
            'risk_score': 0
        }
        
        mac_history_list = self.mac_history.get(mac, [])
        
        if len(mac_history_list) >= 3:
            result['is_flapping'] = True
            result['change_count'] = len(mac_history_list)
            result['risk_score'] = min(90, 40 + len(mac_history_list) * 10)
            result['history'] = mac_history_list
        
        return result
    
    def get_all_anomalies(self, known_devices: Dict) -> List[Dict]:
        """获取所有ARP绑定异常
        
        Args:
            known_devices: 已知设备字典
            
        Returns:
            List: 异常列表
        """
        anomalies = []
        
        for ip, arp_entry in self.arp_table.items():
            mac = arp_entry.mac
            
            known_device = known_devices.get(mac)
            
            if known_device:
                known_ip = known_device.get('ip')
                if known_ip and known_ip != ip:
                    anomalies.append({
                        'type': 'arp_binding_changed',
                        'severity': 'high',
                        'device_ip': ip,
                        'device_mac': mac,
                        'previous_ip': known_ip,
                        'description': f"MAC {mac} 的IP从 {known_ip} 变为 {ip}，可能存在ARP欺骗",
                        'is_spoofing': True
                    })
        
        return anomalies
    
    def get_arp_entry(self, ip: str) -> Optional[ARPTable]:
        """获取指定IP的ARP表项"""
        return self.arp_table.get(ip)
    
    def get_mac_from_ip(self, ip: str) -> Optional[str]:
        """根据IP获取MAC地址"""
        entry = self.get_arp_entry(ip)
        return entry.mac if entry else None
    
    def get_all_bindings(self) -> Dict[str, str]:
        """获取所有IP-MAC绑定"""
        return {ip: entry.mac for ip, entry in self.arp_table.items()}
