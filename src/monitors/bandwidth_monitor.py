#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
带宽监控模块
"""

import logging
import subprocess
import re
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger('LanSecurityMonitor')


class BandwidthMonitor:
    """带宽监控器"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        # 配置项
        self.enable_bandwidth_monitor = config.get_bool('ENABLE_BANDWIDTH_MONITOR', True)
        self.upload_threshold = config.get_int('UPLOAD_THRESHOLD', 512)  # KB/s
        self.download_threshold = config.get_int('DOWNLOAD_THRESHOLD', 2048)  # KB/s
        self.monitor_interval = config.get_int('BANDWIDTH_MONITOR_INTERVAL', 60)  # 秒
        
        # 历史带宽记录
        self.bandwidth_history = {}
    
    def initialize(self):
        """初始化带宽监控器"""
        if self.enable_bandwidth_monitor:
            self.logger.info("初始化带宽监控器")
            self.logger.info(f"上传阈值: {self.upload_threshold} KB/s")
            self.logger.info(f"下载阈值: {self.download_threshold} KB/s")
            self.logger.info(f"监控间隔: {self.monitor_interval}秒")
    
    def monitor_bandwidth(self, devices: Dict) -> List[Dict]:
        """监控带宽使用
        
        Args:
            devices: 当前设备字典
            
        Returns:
            带宽异常列表
        """
        if not self.enable_bandwidth_monitor:
            return []
        
        self.logger.info("开始监控带宽使用")
        
        anomalies = []
        
        # 检查总带宽
        total_bandwidth = self._get_total_bandwidth()
        if total_bandwidth:
            upload, download = total_bandwidth
            
            if upload > self.upload_threshold:
                anomalies.append({
                    'type': 'high_upload_bandwidth',
                    'severity': 'medium',
                    'description': f"上传带宽异常: {upload:.2f} KB/s",
                    'bandwidth': {
                        'upload': upload,
                        'download': download,
                        'threshold': self.upload_threshold
                    }
                })
            
            if download > self.download_threshold:
                anomalies.append({
                    'type': 'high_download_bandwidth',
                    'severity': 'medium',
                    'description': f"下载带宽异常: {download:.2f} KB/s",
                    'bandwidth': {
                        'upload': upload,
                        'download': download,
                        'threshold': self.download_threshold
                    }
                })
        
        # 检查特定设备带宽（如果支持）
        for mac, device in devices.items():
            # 只监控核心设备和NAS
            if device.get('category') in ['core', 'nas']:
                device_bandwidth = self._get_device_bandwidth(device.get('ip'))
                if device_bandwidth:
                    upload, download = device_bandwidth
                    
                    # 为核心设备设置较低的阈值
                    device_upload_threshold = self.upload_threshold / 2
                    device_download_threshold = self.download_threshold / 2
                    
                    if upload > device_upload_threshold:
                        anomalies.append({
                            'device': device,
                            'type': 'device_high_upload',
                            'severity': 'high',
                            'description': f"设备上传带宽异常: {upload:.2f} KB/s",
                            'bandwidth': {
                                'upload': upload,
                                'download': download,
                                'threshold': device_upload_threshold
                            }
                        })
                    
                    if download > device_download_threshold:
                        anomalies.append({
                            'device': device,
                            'type': 'device_high_download',
                            'severity': 'medium',
                            'description': f"设备下载带宽异常: {download:.2f} KB/s",
                            'bandwidth': {
                                'upload': upload,
                                'download': download,
                                'threshold': device_download_threshold
                            }
                        })
        
        return anomalies
    
    def _get_total_bandwidth(self) -> Optional[tuple]:
        """获取总带宽使用
        
        Returns:
            (upload, download) 单位: KB/s
        """
        try:
            # 使用ifconfig或netstat获取网络接口信息
            # 这里使用简化的方法，实际需要根据系统调整
            
            # 对于macOS
            cmd = "netstat -ibn | grep -E '^en|^eth'"
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # 解析输出
            # 示例输出:
            # en0    1500  <Link#4>  00:11:22:33:44:55  0  0  0  0  0  0  0  0
            # en0    1500  192.168.1.100  00:11:22:33:44:55  0  0  0  0  0  0  0  0
            
            # 注意：这种方法只能获取包数量，不能直接获取带宽
            # 实际实现需要使用更专业的工具，如iftop、nethogs等
            
            # 这里返回模拟数据，实际需要替换为真实实现
            return (0, 0)
            
        except Exception as e:
            self.logger.error(f"获取总带宽失败: {str(e)}")
            return None
    
    def _get_device_bandwidth(self, ip: str) -> Optional[tuple]:
        """获取特定设备带宽使用
        
        Args:
            ip: 设备IP地址
            
        Returns:
            (upload, download) 单位: KB/s
        """
        try:
            # 使用nethogs或iftop获取设备带宽
            # 这里使用简化的方法
            
            # 示例：使用iftop
            cmd = f"iftop -t -s 1 -n | grep {ip}"
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # 解析输出
            # 示例输出:
            # 192.168.1.100    =>    1.2.3.4       10Kb  20Kb  15Kb
            #                        <=               5Kb   8Kb   6Kb
            
            # 这里返回模拟数据，实际需要替换为真实实现
            return (0, 0)
            
        except Exception as e:
            self.logger.error(f"获取设备带宽失败: {str(e)}")
            return None
    
    def cleanup(self):
        """清理资源"""
        self.logger.info("清理带宽监控器资源")