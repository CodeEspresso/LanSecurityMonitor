#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bark通知器模块
"""

import logging
import requests
import time
from datetime import datetime
from typing import Optional, Dict


class BarkNotifier:
    """Bark通知器"""
    
    def __init__(self, config, secure_config=None):
        self.config = config
        self.secure_config = secure_config
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        # 基础配置
        self.enabled = config.get_bool('ENABLE_BARK', True)
        self.server = config.get('BARK_SERVER', 'https://api.day.app')
        
        # 密钥从环境变量读取（安全）
        self.key = self._get_key()
        
        if not self.key:
            self.logger.warning("Bark密钥未配置，Bark通知将不可用")
        
        self.alert_level = config.get('BARK_ALERT_LEVEL', 'medium')
        
        # 通知策略配置
        self.notify_smart_home = config.get_bool('NOTIFY_SMART_HOME_CHANGES', False)
        self.notify_first_seen_immediately = config.get_bool('NOTIFY_FIRST_SEEN_IMMEDIATELY', False)
        self.silent_periods = self._parse_silent_periods(config.get('SILENT_PERIODS', ''))
        self.notify_by_category = config.get_bool('NOTIFY_BY_CATEGORY', True)
        self.cooldown_minutes = config.get_int('NOTIFICATION_COOLDOWN', 15)
        
        # 通知冷却记录
        self.notification_history = {}
    
    def _get_key(self):
        """获取密钥（优先从secure_config获取）"""
        if self.secure_config:
            return self.secure_config.get('BARK_KEY', '')
        return self.config.get('BARK_KEY', '')
    
    def send_alert(self, title: str, message: str, severity: str = 'medium', device: Optional[Dict] = None, is_threat: bool = False) -> bool:
        """发送告警通知
        
        Args:
            title: 标题
            message: 消息内容
            severity: 严重程度（low/medium/high/critical）
            device: 设备信息（可选）
            is_threat: 是否为威胁通知（威胁通知不受某些限制）
            
        Returns:
            bool: 是否发送成功
        """
        if not self.enabled:
            self.logger.debug("Bark通知已禁用")
            return False
        
        if not self.key:
            self.logger.warning("Bark Key未配置，跳过通知")
            return False
        
        # 检查是否在静默时段（威胁通知不受静默时段限制）
        if not is_threat and self._is_in_silent_period():
            self.logger.debug("当前处于静默时段，跳过通知")
            return False
        
        # 检查设备类型通知策略（威胁通知不受设备类型限制）
        if not is_threat and device and not self._should_notify_device(device):
            self.logger.debug(f"设备类型 {device.get('device_type')} 不需要通知")
            return False
        
        # 检查告警级别（威胁通知不受告警级别限制）
        if not is_threat and not self._should_send(severity):
            self.logger.debug(f"告警级别 {severity} 低于阈值 {self.alert_level}，跳过通知")
            return False
        
        # 检查通知冷却
        notification_key = self._get_notification_key(title, device)
        if not self._check_cooldown(notification_key):
            self.logger.debug(f"通知 {notification_key} 处于冷却期，跳过通知")
            return False
        
        try:
            # 构建URL
            url = f"{self.server}/{self.key}/{title}/{message}"
            
            # 添加图标和声音
            params = {
                'icon': self._get_icon(severity),
                'sound': self._get_sound(severity),
                'group': '局域网安全'
            }
            
            # 发送请求
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                self.logger.info(f"Bark通知发送成功: {title}")
                # 更新通知历史
                self._update_notification_history(notification_key)
                return True
            else:
                self.logger.error(f"Bark通知发送失败: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Bark通知发送异常: {str(e)}")
            return False
    
    def _should_notify_device(self, device: Dict) -> bool:
        """判断是否应该通知设备相关事件"""
        device_type = device.get('device_type')
        category = device.get('category')
        
        # 智能家居设备配置
        if device_type == 'smart_home' or category == 'iot':
            return self.notify_smart_home
        
        return True
    
    def _is_in_silent_period(self) -> bool:
        """判断是否在静默时段"""
        current_hour = datetime.now().hour
        
        for start, end in self.silent_periods:
            if start <= current_hour < end:
                return True
        
        return False
    
    def _parse_silent_periods(self, periods_str: str) -> list:
        """解析静默时段"""
        periods = []
        
        if not periods_str:
            return periods
        
        for period in periods_str.split(','):
            period = period.strip()
            if '-' in period:
                try:
                    start, end = map(int, period.split('-'))
                    if 0 <= start < 24 and 0 <= end <= 24:
                        periods.append((start, end))
                except ValueError:
                    self.logger.error(f"静默时段格式错误: {period}")
        
        return periods
    
    def _get_notification_key(self, title: str, device: Optional[Dict] = None) -> str:
        """获取通知唯一键"""
        if device and self.notify_by_category:
            category = device.get('category', 'unknown')
            return f"{category}:{title}"
        return title
    
    def _check_cooldown(self, notification_key: str) -> bool:
        """检查通知冷却"""
        last_notification = self.notification_history.get(notification_key, 0)
        current_time = time.time()
        
        cooldown_seconds = self.cooldown_minutes * 60
        
        return current_time - last_notification > cooldown_seconds
    
    def _update_notification_history(self, notification_key: str):
        """更新通知历史"""
        self.notification_history[notification_key] = time.time()
    
    def _should_send(self, severity: str) -> bool:
        """判断是否应该发送通知"""
        levels = ['low', 'medium', 'high', 'critical']
        
        try:
            severity_index = levels.index(severity.lower())
            threshold_index = levels.index(self.alert_level.lower())
            return severity_index >= threshold_index
        except ValueError:
            return True
    
    def _get_icon(self, severity: str) -> str:
        """获取图标"""
        icons = {
            'low': 'ℹ️',
            'medium': '⚠️',
            'high': '🚨',
            'critical': '🔴'
        }
        return icons.get(severity.lower(), 'ℹ️')
    
    def _get_sound(self, severity: str) -> str:
        """获取声音"""
        sounds = {
            'low': 'bell',
            'medium': 'glass',
            'high': 'alarm',
            'critical': 'anticipate'
        }
        return sounds.get(severity.lower(), 'bell')
