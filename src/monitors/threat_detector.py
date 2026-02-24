#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
威胁检测器模块
"""

import logging
from typing import Dict, List, Optional

from .device_risk_analyzer import DeviceRiskAnalyzer

try:
    from ..ml.risk_enhancer import MLRiskEnhancer
    from ..ml.behavior_detector import MLBehaviorDetector
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


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
        
        self.enable_ml_risk = config.get_bool('ENABLE_ML_RISK', True) and ML_AVAILABLE
        self.enable_ml_behavior = config.get_bool('ENABLE_ML_BEHAVIOR', True) and ML_AVAILABLE
        self.ml_risk_enhancer: Optional[MLRiskEnhancer] = None
        self.ml_behavior_detector: Optional[MLBehaviorDetector] = None
    
    def initialize(self):
        """初始化威胁检测器"""
        self.logger.info("初始化威胁检测器")
        
        if self.enable_risk_analysis:
            self.risk_analyzer = DeviceRiskAnalyzer(self.config, self.database)
            self.risk_analyzer.initialize()
            self.logger.info("已启用设备风险评估功能")
        
        if self.enable_ml_risk:
            try:
                self.ml_risk_enhancer = MLRiskEnhancer(self.config, self.database)
                self.ml_risk_enhancer.initialize()
                self.logger.info("已启用ML风险增强功能")
            except Exception as e:
                self.logger.warning(f"ML风险增强初始化失败: {e}")
                self.enable_ml_risk = False
        
        if self.enable_ml_behavior:
            try:
                self.ml_behavior_detector = MLBehaviorDetector(self.config, self.database)
                self.ml_behavior_detector.initialize()
                self.logger.info("已启用ML行为异常检测功能")
            except Exception as e:
                self.logger.warning(f"ML行为检测初始化失败: {e}")
                self.enable_ml_behavior = False
        
        self.log_ml_status()
    
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
                        
                        if self.enable_ml_risk and self.ml_risk_enhancer:
                            risk_result = self.ml_risk_enhancer.enhance_risk_assessment(device, risk_result)
                            self.logger.info(f"ML增强风险评估: 设备 {device.get('ip')}, 分数: {risk_result.get('enhanced_score', risk_result.get('risk_score'))}")
                        
                        severity = self._map_risk_level_to_severity(risk_result.get('risk_level', 'medium'))
                        
                        threats.append({
                            'device': device,
                            'type': 'unknown_device',
                            'severity': severity,
                            'description': f"未知设备接入: {device.get('ip')} ({mac}) - {reason}",
                            'risk_score': risk_result.get('enhanced_score', risk_result.get('risk_score')),
                            'risk_level': risk_result.get('risk_level'),
                            'risk_details': risk_result.get('score_details', {}),
                            'ml_enhanced': risk_result.get('ml_enhanced', False),
                            'ml_prediction': risk_result.get('ml_prediction'),
                            'recommendations': risk_result.get('recommendations', [])
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
        
        threats.extend(self._detect_abnormal_ports(devices))
        
        return threats
    
    def _detect_abnormal_ports(self, devices: Dict) -> List[Dict]:
        """检测异常端口
        
        Args:
            devices: 设备字典
            
        Returns:
            威胁列表
        """
        threats = []
        
        for mac, device in devices.items():
            if mac in self.whitelist_macs:
                continue
            
            open_ports = device.get('open_ports', [])
            port_details = device.get('port_details', [])
            
            if not open_ports:
                continue
            
            suspicious_found = []
            for port in open_ports:
                if str(port) in [str(p) for p in self.suspicious_ports]:
                    suspicious_found.append(port)
            
            if suspicious_found:
                severity = 'high' if len(suspicious_found) > 1 else 'medium'
                threats.append({
                    'device': device,
                    'type': 'suspicious_port',
                    'severity': severity,
                    'description': f"检测到可疑端口: {suspicious_found} 在设备 {device.get('ip')}",
                    'risk_score': 80,
                    'risk_level': 'high',
                    'suspicious_ports': suspicious_found,
                    'open_ports': open_ports
                })
                self.logger.warning(f"⚠️ 设备 {device.get('ip')} 开放可疑端口: {suspicious_found}")
            
            port_count = device.get('port_count', 0)
            if port_count >= 5:
                threats.append({
                    'device': device,
                    'type': 'many_open_ports',
                    'severity': 'medium',
                    'description': f"设备 {device.get('ip')} 开放过多端口: {port_count}个",
                    'risk_score': 60,
                    'risk_level': 'medium',
                    'open_ports': open_ports,
                    'port_count': port_count
                })
                self.logger.info(f"ℹ️  设备 {device.get('ip')} 开放 {port_count} 个端口")
        
        return threats
    
    def detect_known_device_anomalies(self, devices: Dict) -> List[Dict]:
        """检测已知设备的异常行为
        
        Args:
            devices: 当前设备字典
            
        Returns:
            异常列表
        """
        anomalies = []
        
        if not self.enable_ml_behavior or not self.ml_behavior_detector:
            return anomalies
        
        for mac, device in devices.items():
            if not device.get('is_known', False):
                continue
            
            try:
                behavior_data = {
                    'behavior_history': [],
                    'network_activity_score': 50,
                    'session_duration_hours': device.get('online_hours', 0),
                    'last_seen_timestamp': device.get('last_seen')
                }
                
                result = self.ml_behavior_detector.detect_anomaly(device, behavior_data)
                
                if result.get('is_anomaly'):
                    self.logger.info(f"🔍 ML行为检测: 设备 {device.get('ip')} 存在异常 - {result.get('details', [])}")
                    anomalies.append({
                        'device': device,
                        'type': 'behavior_anomaly',
                        'severity': 'medium',
                        'description': f"设备行为异常: {', '.join(result.get('details', []))}",
                        'anomaly_score': result.get('anomaly_score', 0),
                        'ml_enhanced': True
                    })
            except Exception as e:
                self.logger.debug(f"行为检测跳过设备 {mac}: {e}")
        
        return anomalies
    
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
    
    def get_ml_status(self) -> Dict:
        """获取ML模块状态
        
        Returns:
            ML状态信息字典
        """
        status = {
            'ml_available': ML_AVAILABLE,
            'ml_risk_enabled': self.enable_ml_risk,
            'ml_behavior_enabled': self.enable_ml_behavior,
            'risk_model': None,
            'behavior_model': None
        }
        
        if self.enable_ml_risk and self.ml_risk_enhancer:
            status['risk_model'] = self.ml_risk_enhancer.get_model_info()
        
        if self.enable_ml_behavior and self.ml_behavior_detector:
            status['behavior_model'] = self.ml_behavior_detector.get_model_info()
        
        return status
    
    def log_ml_status(self):
        """记录ML模块状态到日志"""
        self.logger.info("=" * 50)
        self.logger.info("🤖 ML模块状态")
        self.logger.info("=" * 50)
        
        if not ML_AVAILABLE:
            self.logger.info("⚠️  scikit-learn 未安装，ML功能不可用")
            self.logger.info("   请运行: pip install scikit-learn")
            return
        
        status = self.get_ml_status()
        
        self.logger.info(f"ML库可用: ✅")
        self.logger.info(f"ML风险增强: {'✅ 已启用' if status['ml_risk_enabled'] else '❌ 未启用'}")
        self.logger.info(f"ML行为检测: {'✅ 已启用' if status['ml_behavior_enabled'] else '❌ 未启用'}")
        
        if status['risk_model']:
            rm = status['risk_model']
            self.logger.info(f"  风险模型: {'已训练' if rm.get('is_trained') else '未训练'} ({rm.get('model_type', 'N/A')})")
        
        if status['behavior_model']:
            bm = status['behavior_model']
            self.logger.info(f"  行为模型: {'已训练' if bm.get('is_trained') else '未训练'} ({bm.get('model_type', 'N/A')})")
        
        self.logger.info("=" * 50)
