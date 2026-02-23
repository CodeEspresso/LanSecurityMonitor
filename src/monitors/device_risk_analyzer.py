#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
设备风险评估器模块
基于多维度特征对设备进行ML风险评估
"""

import logging
import re
from typing import Dict, List, Tuple
from datetime import datetime

logger = logging.getLogger('LanSecurityMonitor')


class DeviceRiskAnalyzer:
    """设备风险评估器"""
    
    TRUSTED_VENDORS = {
        '小米', '华为', 'Apple', 'Synology', 'QNAP', '群晖', '威联通',
        '海康威视', '萤石', '绿米', '涂鸦智能', '乐鑫科技',
        'Intel', 'HP', 'Dell', 'Lenovo', 'ASUS', 'Netgear',
        'Nintendo', 'Xbox', 'PlayStation', 'VMware',
        'Xiaomi', 'Huawei', 'Espressif', 'Tuya', 'Aqara', 'Yeelight',
        'Cisco', 'TP-Link', 'Ubiquiti', 'MikroTik', 'Juniper', 'Aruba'
    }
    
    IOT_VENDORS = {
        '小米', '涂鸦智能', '绿米', '乐鑫科技', '萤石', '海康威视',
        'Espressif', 'Tuya', 'Aqara', 'Yeelight'
    }
    
    NETWORK_INFRASTRUCTURE_VENDORS = {
        'Cisco', 'Huawei', 'TP-Link', 'Netgear', 'Ubiquiti', 'MikroTik',
        'Juniper', 'Aruba', 'Ruckus'
    }
    
    def __init__(self, config, database=None):
        self.config = config
        self.database = database
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        self.risk_threshold = config.get_int('DEVICE_RISK_THRESHOLD', 60)
        self.high_risk_threshold = config.get_int('HIGH_RISK_THRESHOLD', 80)
    
    def initialize(self):
        """初始化风险评估器"""
        self.logger.info("初始化设备风险评估器")
        self.logger.info(f"风险阈值: {self.risk_threshold}, 高风险阈值: {self.high_risk_threshold}")
    
    def analyze_device_risk(self, device: Dict) -> Dict:
        """分析设备风险
        
        Args:
            device: 设备信息
            
        Returns:
            风险评估结果
        """
        scores = {}
        weights = {}
        
        scores['vendor'], weights['vendor'] = self._score_vendor(device)
        scores['device_type'], weights['device_type'] = self._score_device_type(device)
        scores['ip_pattern'], weights['ip_pattern'] = self._score_ip_pattern(device)
        scores['mac_pattern'], weights['mac_pattern'] = self._score_mac_pattern(device)
        scores['network_role'], weights['network_role'] = self._score_network_role(device)
        
        total_weight = sum(weights.values())
        weighted_score = sum(scores[k] * weights[k] for k in scores) / total_weight if total_weight > 0 else 50
        
        risk_level = self._determine_risk_level(weighted_score)
        
        return {
            'device': device,
            'risk_score': round(weighted_score, 1),
            'risk_level': risk_level,
            'score_details': scores,
            'weight_details': weights,
            'recommendations': self._generate_recommendations(device, weighted_score, scores),
            'should_alert': weighted_score >= self.risk_threshold
        }
    
    def _score_vendor(self, device: Dict) -> Tuple[float, float]:
        """评估厂商风险
        
        Returns:
            (风险分数0-100, 权重)
        """
        vendor = device.get('vendor', '')
        weight = 2.5
        
        if not vendor:
            mac = device.get('mac', '')
            if self._is_random_mac(mac):
                return 45.0, weight
            return 70.0, weight
        
        vendor_lower = vendor.lower()
        
        for trusted in self.TRUSTED_VENDORS:
            if trusted.lower() in vendor_lower:
                return 20.0, weight
        
        for iot_vendor in self.IOT_VENDORS:
            if iot_vendor.lower() in vendor_lower:
                return 40.0, weight
        
        for infra_vendor in self.NETWORK_INFRASTRUCTURE_VENDORS:
            if infra_vendor.lower() in vendor_lower:
                return 15.0, weight
        
        return 60.0, weight
    
    def _is_random_mac(self, mac: str) -> bool:
        """检测是否为随机MAC地址
        
        Args:
            mac: MAC地址
            
        Returns:
            是否为随机MAC
        """
        if not mac:
            return False
        
        mac_clean = mac.replace(':', '').lower()
        if len(mac_clean) >= 2:
            second_char = mac_clean[1]
            if second_char in ['2', '6', 'a', 'e']:
                return True
        return False
    
    def _score_device_type(self, device: Dict) -> Tuple[float, float]:
        """评估设备类型风险
        
        Returns:
            (风险分数0-100, 权重)
        """
        device_type = device.get('device_type', 'unknown')
        category = device.get('category', 'unknown')
        weight = 1.5
        
        type_scores = {
            'nas': 25.0,
            'computer': 30.0,
            'personal_device': 25.0,
            'mobile': 25.0,
            'smart_home': 45.0,
            'camera': 40.0,
            'tv': 35.0,
            'game_console': 30.0,
            'printer': 35.0,
            'virtual_machine': 40.0,
            'router': 10.0,
            'gateway': 10.0,
            'switch': 10.0,
            'unknown': 55.0
        }
        
        category_scores = {
            'core': 25.0,
            'infrastructure': 10.0,
            'iot': 45.0,
            'entertainment': 30.0,
            'security': 40.0,
            'peripheral': 35.0,
            'virtual': 40.0,
            'unknown': 50.0
        }
        
        type_score = type_scores.get(device_type, 55.0)
        category_score = category_scores.get(category, 50.0)
        
        if device_type == 'unknown' and self._is_random_mac(device.get('mac', '')):
            type_score = 35.0
            category_score = 30.0
        
        return (type_score + category_score) / 2, weight
    
    def _score_ip_pattern(self, device: Dict) -> Tuple[float, float]:
        """评估IP地址模式风险
        
        Returns:
            (风险分数0-100, 权重)
        """
        ip = device.get('ip', '')
        weight = 1.5
        
        if not ip:
            return 80.0, weight
        
        if ip.endswith('.1') or ip.endswith('.254'):
            return 15.0, weight
        
        parts = ip.split('.')
        if len(parts) == 4:
            last_octet = int(parts[3])
            
            if last_octet <= 10:
                return 25.0, weight
            elif last_octet <= 50:
                return 35.0, weight
            elif last_octet <= 100:
                return 45.0, weight
            elif last_octet <= 200:
                return 50.0, weight
            else:
                return 55.0, weight
        
        return 50.0, weight
    
    def _score_mac_pattern(self, device: Dict) -> Tuple[float, float]:
        """评估MAC地址模式风险
        
        检测是否为随机MAC地址（隐私地址）
        注意：苹果设备（iPhone、Apple Watch等）使用随机MAC是正常的隐私保护行为
        
        Returns:
            (风险分数0-100, 权重)
        """
        mac = device.get('mac', '')
        weight = 1.0
        
        if not mac:
            return 80.0, weight
        
        mac_clean = mac.replace(':', '').lower()
        
        if len(mac_clean) >= 2:
            second_char = mac_clean[1]
            if second_char in ['2', '6', 'a', 'e']:
                self.logger.debug(f"检测到随机MAC地址: {mac}（可能是苹果设备的隐私保护功能）")
                return 35.0, weight
        
        return 30.0, weight
    
    def _score_network_role(self, device: Dict) -> Tuple[float, float]:
        """评估网络角色风险
        
        Returns:
            (风险分数0-100, 权重)
        """
        ip = device.get('ip', '')
        hostname = device.get('hostname', '')
        weight = 1.0
        
        if ip.endswith('.1'):
            return 10.0, weight
        
        if hostname:
            hostname_lower = hostname.lower()
            if any(key in hostname_lower for key in ['router', 'gateway', 'switch', 'nas', 'server']):
                return 15.0, weight
        
        return 50.0, weight
    
    def _determine_risk_level(self, score: float) -> str:
        """确定风险等级
        
        Args:
            score: 风险分数 (0-100)
            
        Returns:
            风险等级
        """
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        else:
            return 'safe'
    
    def _generate_recommendations(self, device: Dict, score: float, scores: Dict) -> List[str]:
        """生成建议
        
        Args:
            device: 设备信息
            score: 总风险分数
            scores: 各维度分数
            
        Returns:
            建议列表
        """
        recommendations = []
        
        if score >= self.high_risk_threshold:
            recommendations.append("高风险设备，建议立即审查并考虑隔离")
        
        if scores.get('vendor', 0) >= 60:
            vendor = device.get('vendor', '')
            if vendor:
                recommendations.append(f"厂商 '{vendor}' 不在信任列表中，建议确认设备来源")
            else:
                recommendations.append("无法识别设备厂商，建议手动确认设备身份")
        
        if scores.get('mac_pattern', 0) >= 60:
            recommendations.append("设备使用随机MAC地址（隐私保护），可能是移动设备")
        
        if scores.get('device_type', 0) >= 60:
            recommendations.append("设备类型未知，建议进一步调查")
        
        if not recommendations:
            recommendations.append("设备风险较低，可标记为已知设备")
        
        return recommendations
    
    def analyze_devices(self, devices: List[Dict]) -> List[Dict]:
        """批量分析设备风险
        
        Args:
            devices: 设备列表
            
        Returns:
            风险评估结果列表
        """
        results = []
        for device in devices:
            result = self.analyze_device_risk(device)
            results.append(result)
        
        results.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return results
    
    def should_alert_for_new_device(self, device: Dict) -> Tuple[bool, str]:
        """判断是否应该对新设备发出警报
        
        Args:
            device: 设备信息
            
        Returns:
            (是否应该警报, 原因)
        """
        result = self.analyze_device_risk(device)
        score = result['risk_score']
        risk_level = result['risk_level']
        
        if score >= self.high_risk_threshold:
            return True, f"高风险设备 (评分: {score}, 等级: {risk_level})"
        elif score >= self.risk_threshold:
            return True, f"中等风险设备 (评分: {score}, 等级: {risk_level})"
        else:
            return False, f"低风险设备 (评分: {score}, 等级: {risk_level})，已自动标记为已知"
