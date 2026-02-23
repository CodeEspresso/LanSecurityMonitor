#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
威胁检测器模块
"""

import logging
from typing import Dict, List, Optional

from .device_risk_analyzer import DeviceRiskAnalyzer


class ThreatDetector:
    """威胁检测器"""
    
    def __init__(self, config, database=None):
        self.config = config
        self.database = database
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        self.suspicious_ports = config.get_list('SUSPICIOUS_PORTS', ['4444', '5555', '6666'])
        self.whitelist_macs = config.get_list('WHITELIST_MACS', [])
        
        self.enable_risk_analysis = config.get_bool('ENABLE_RISK_ANALYSIS', True)
        self.risk_analyzer: Optional[DeviceRiskAnalyzer] = None
    
    def initialize(self):
        """初始化威胁检测器"""
        self.logger.info("初始化威胁检测器")
        
        if self.enable_risk_analysis:
            self.risk_analyzer = DeviceRiskAnalyzer(self.config, self.database)
            self.risk_analyzer.initialize()
            self.logger.info("已启用设备风险评估功能")
    
    def detect_threats(self, devices: Dict, known_devices: Dict = None) -> List[Dict]:
        """检测威胁
        
        Args:
            devices: 当前扫描到的设备字典
            known_devices: 已知设备字典（可选）
        
        Returns:
            List[Dict]: 威胁列表
        """
        threats = []
        
        for mac, device in devices.items():
            if mac in self.whitelist_macs:
                continue
            
            if not device.get('is_known', False):
                if known_devices and mac in known_devices:
                    continue
                
                if self.enable_risk_analysis and self.risk_analyzer:
                    should_alert, reason = self.risk_analyzer.should_alert_for_new_device(device)
                    
                    if should_alert:
                        risk_result = self.risk_analyzer.analyze_device_risk(device)
                        severity = self._map_risk_level_to_severity(risk_result['risk_level'])
                        
                        threats.append({
                            'device': device,
                            'type': 'unknown_device',
                            'severity': severity,
                            'description': f"未知设备接入: {device.get('ip')} ({mac}) - {reason}",
                            'risk_score': risk_result['risk_score'],
                            'risk_details': risk_result['score_details'],
                            'recommendations': risk_result['recommendations']
                        })
                    else:
                        self.logger.info(f"新设备风险较低，自动标记为已知: {device.get('ip')} ({mac}) - {reason}")
                        device['is_known'] = True
                        if self.database:
                            self.database.save_device(device)
                else:
                    threats.append({
                        'device': device,
                        'type': 'unknown_device',
                        'severity': 'medium',
                        'description': f"未知设备接入: {device.get('ip')} ({mac})"
                    })
        
        return threats
    
    def _map_risk_level_to_severity(self, risk_level: str) -> str:
        """将风险等级映射到威胁严重程度
        
        Args:
            risk_level: 风险等级
            
        Returns:
            威胁严重程度
        """
        mapping = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'safe': 'low'
        }
        return mapping.get(risk_level, 'medium')
    
    def analyze_device_risk(self, device: Dict) -> Dict:
        """分析设备风险（供外部调用）
        
        Args:
            device: 设备信息
            
        Returns:
            风险评估结果
        """
        if self.risk_analyzer:
            return self.risk_analyzer.analyze_device_risk(device)
        return {'risk_score': 50, 'risk_level': 'medium', 'should_alert': True}
