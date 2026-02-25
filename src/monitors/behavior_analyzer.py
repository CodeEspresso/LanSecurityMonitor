#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
设备行为分析器模块
"""

import logging
import json
from typing import Dict, List, Optional
from datetime import datetime, time

logger = logging.getLogger('LanSecurityMonitor')


class BehaviorAnalyzer:
    """设备行为分析器"""
    
    def __init__(self, config, database):
        self.config = config
        self.database = database
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        # 配置项
        self.enable_behavior_analysis = config.get_bool('ENABLE_BEHAVIOR_ANALYSIS', True)
        self.min_observations = config.get_int('MIN_OBSERVATIONS', 7)
        self.anomaly_threshold = config.get_int('ANOMALY_THRESHOLD', 3)
        self.learning_period_days = config.get_int('LEARNING_PERIOD_DAYS', 30)
        self.active_hour_threshold = config.get_float('ACTIVE_HOUR_THRESHOLD', 0.6)
        self.active_hour_tolerance = config.get_int('ACTIVE_HOUR_TOLERANCE', 1)
    
    def initialize(self):
        """初始化行为分析器"""
        if self.enable_behavior_analysis:
            self.logger.info("初始化设备行为分析器")
            self.logger.info(f"最小观察次数: {self.min_observations}")
            self.logger.info(f"异常阈值: {self.anomaly_threshold}")
            self.logger.info(f"学习周期: {self.learning_period_days}天")
            self.logger.info(f"活跃时间阈值: {self.active_hour_threshold}")
            self.logger.info(f"活跃时间容差: ±{self.active_hour_tolerance}小时")
    
    def analyze_device_behavior(self, devices: Dict) -> List[Dict]:
        """分析设备行为
        
        Args:
            devices: 当前设备字典
            
        Returns:
            行为异常列表
        """
        if not self.enable_behavior_analysis:
            return []
        
        # 检查是否为首次运行
        if self.database.is_first_run():
            self.logger.info("首次运行模式，跳过行为分析但记录行为数据")
            # 即使跳过分析，也要记录行为数据
            for mac, device in devices.items():
                if not self._is_critical_device(device):
                    self._record_device_behavior(mac, device)
            return []
        
        # 检查是否应该进行行为分析
        total_devices = self.database.get_total_devices_count()
        if total_devices < 10:
            self.logger.info(f"设备数量为 {total_devices}，跳过行为分析（需要至少10个设备）")
            # 仍然记录行为数据，以便后续分析
            for mac, device in devices.items():
                if not self._is_critical_device(device):
                    self._record_device_behavior(mac, device)
            return []
        
        self.logger.info("开始分析设备行为")
        
        anomalies = []
        
        for mac, device in devices.items():
            self.logger.debug(f"分析设备行为: {device.get('hostname', mac)}")
            
            # 跳过网关/路由器等关键设备
            if self._is_critical_device(device):
                self.logger.debug(f"跳过关键设备: {device.get('hostname', mac)}")
                continue
            
            # 先记录当前行为（即使历史不足也记录，逐步积累）
            self._record_device_behavior(mac, device)
            
            # 检查是否有足够的历史数据进行分析
            if not self._has_sufficient_history(mac):
                self.logger.debug(f"设备 {mac} 历史数据不足，跳过分析")
                continue
            
            # 分析行为模式
            behavior_pattern = self._get_device_behavior_pattern(mac)
            
            if behavior_pattern:
                # 检查是否异常
                is_anomalous, reason = self._is_behavior_anomalous(device, behavior_pattern)
                
                if is_anomalous:
                    anomalies.append({
                        'device': device,
                        'type': 'behavior_anomaly',
                        'severity': 'medium',
                        'description': f"设备行为异常: {reason}",
                        'behavior_pattern': behavior_pattern
                    })
        
        return anomalies
    
    def _record_device_behavior(self, mac: str, device: Dict):
        """记录设备行为
        
        Args:
            mac: 设备MAC地址
            device: 设备信息
        """
        try:
            # 记录在线时间
            timestamp = datetime.now()
            hour = timestamp.hour
            day_of_week = timestamp.weekday()  # 0=周一, 6=周日
            
            # 保存到数据库
            self.database.save_device_behavior({
                'mac': mac,
                'ip': device.get('ip'),
                'hostname': device.get('hostname'),
                'timestamp': timestamp.isoformat(),
                'hour': hour,
                'day_of_week': day_of_week,
                'status': 'online'
            })
            
        except Exception as e:
            self.logger.error(f"记录设备行为失败: {str(e)}")
    
    def _get_device_behavior_pattern(self, mac: str) -> Optional[Dict]:
        """获取设备行为模式
        
        Args:
            mac: 设备MAC地址
            
        Returns:
            行为模式
        """
        try:
            # 从数据库获取行为记录
            behaviors = self.database.get_device_behaviors(mac, days=self.learning_period_days)
            
            if len(behaviors) < self.min_observations:
                self.logger.debug(f"设备观察次数不足: {len(behaviors)}次")
                return None
            
            # 分析行为模式
            pattern = {
                'mac': mac,
                'observation_count': len(behaviors),
                'hourly_pattern': self._analyze_hourly_pattern(behaviors),
                'daily_pattern': self._analyze_daily_pattern(behaviors),
                'last_updated': datetime.now().isoformat()
            }
            
            return pattern
            
        except Exception as e:
            self.logger.error(f"获取设备行为模式失败: {str(e)}")
            return None
    
    def _analyze_hourly_pattern(self, behaviors: List[Dict]) -> Dict:
        """分析小时行为模式
        
        Args:
            behaviors: 行为记录列表
            
        Returns:
            小时行为模式
        """
        hourly_counts = {hour: 0 for hour in range(24)}
        
        for behavior in behaviors:
            hour = behavior.get('hour', 0)
            if 0 <= hour < 24:
                hourly_counts[hour] += 1
        
        # 计算活跃度（0-1）
        max_count = max(hourly_counts.values()) if hourly_counts else 1
        hourly_activity = {hour: count / max_count for hour, count in hourly_counts.items()}
        
        # 识别活跃时间段
        active_hours = [hour for hour, activity in hourly_activity.items() if activity > self.active_hour_threshold]
        
        return {
            'counts': hourly_counts,
            'activity': hourly_activity,
            'active_hours': active_hours
        }
    
    def _analyze_daily_pattern(self, behaviors: List[Dict]) -> Dict:
        """分析每日行为模式
        
        Args:
            behaviors: 行为记录列表
            
        Returns:
            每日行为模式
        """
        daily_counts = {day: 0 for day in range(7)}
        
        for behavior in behaviors:
            day = behavior.get('day_of_week', 0)
            if 0 <= day < 7:
                daily_counts[day] += 1
        
        # 计算活跃度（0-1）
        max_count = max(daily_counts.values()) if daily_counts else 1
        daily_activity = {day: count / max_count for day, count in daily_counts.items()}
        
        # 识别活跃天数
        active_days = [day for day, activity in daily_activity.items() if activity > 0.3]
        
        return {
            'counts': daily_counts,
            'activity': daily_activity,
            'active_days': active_days
        }
    
    def _is_behavior_anomalous(self, device: Dict, behavior_pattern: Dict) -> tuple:
        """判断行为是否异常
        
        Args:
            device: 设备信息
            behavior_pattern: 行为模式
            
        Returns:
            (是否异常, 异常原因)
        """
        now = datetime.now()
        current_hour = now.hour
        current_day = now.weekday()
        
        hourly_pattern = behavior_pattern.get('hourly_pattern', {})
        active_hours = hourly_pattern.get('active_hours', [])
        
        daily_pattern = behavior_pattern.get('daily_pattern', {})
        active_days = daily_pattern.get('active_days', [])
        
        if self._is_always_online_device(active_hours, active_days):
            self.logger.debug(f"设备 {device.get('mac')} 识别为一直在线设备，跳过异常检测")
            return False, ""
        
        if self._is_mobile_device(device):
            self.logger.debug(f"设备 {device.get('mac')} 识别为移动设备，跳过时间异常检测")
            return False, ""
        
        if len(active_hours) < 3:
            self.logger.debug(f"设备 {device.get('mac')} 活跃时间数据不足，跳过异常检测")
            return False, ""
        
        if current_hour not in active_hours:
            if self._is_within_tolerance(current_hour, active_hours, self.active_hour_tolerance):
                self.logger.debug(f"设备 {device.get('mac')} 当前时间 {current_hour} 在活跃时间容差范围内")
                return False, ""
            return True, f"设备在非活跃时间上线 (当前: {current_hour}:00, 活跃时间: {active_hours})"
        
        if current_day not in active_days:
            return True, f"设备在非活跃日期上线 (当前: {self._get_day_name(current_day)}, 活跃日期: {[self._get_day_name(d) for d in active_days]})"
        
        return False, ""
    
    def _is_mobile_device(self, device: Dict) -> bool:
        """判断是否为移动设备
        
        Args:
            device: 设备信息
            
        Returns:
            是否为移动设备
        """
        device_type = device.get('device_type', '')
        category = device.get('category', '')
        
        if device_type in ['mobile', 'personal_device', 'smart_home']:
            return True
        
        if category in ['core', 'iot']:
            return True
        
        mac = device.get('mac', '')
        if self._is_random_mac(mac):
            return True
        
        return False
    
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
    
    def _get_day_name(self, day: int) -> str:
        """获取星期名称
        
        Args:
            day: 星期数 (0=周一)
            
        Returns:
            星期名称
        """
        day_names = ['周一', '周二', '周三', '周四', '周五', '周六', '周日']
        return day_names[day] if 0 <= day < 7 else '未知'
    
    def _is_within_tolerance(self, current_hour: int, active_hours: list, tolerance: int) -> bool:
        if tolerance <= 0 or not active_hours:
            return False
        for hour in active_hours:
            if abs(current_hour - hour) <= tolerance:
                return True
        return False
    
    def _is_always_online_device(self, active_hours: list, active_days: list) -> bool:
        """判断是否为一直在线设备
        
        Args:
            active_hours: 活跃小时列表
            active_days: 活跃日期列表
            
        Returns:
            是否为一直在线设备
        """
        # 如果活跃小时数 >= 20，认为是一直在线的
        if len(active_hours) >= 20:
            return True
        
        # 如果活跃天数 >= 7，认为是一直在线的
        if len(active_days) >= 7:
            return True
        
        return False
    
    def _is_critical_device(self, device: Dict) -> bool:
        """判断是否为关键设备（网关/路由器等）
        
        Args:
            device: 设备信息
            
        Returns:
            是否为关键设备
        """
        ip = device.get('ip', '')
        mac = device.get('mac', '')
        device_type = device.get('device_type', '')
        category = device.get('category', '')
        
        # 检查IP地址
        # 网关IP（通常是 .1 或 .254）
        if ip.endswith('.1') or ip.endswith('.254'):
            return True
        
        # 检查设备类型
        if device_type in ['router', 'gateway', 'switch']:
            return True
        
        # 检查设备分类
        if category in ['network', 'infrastructure']:
            return True
        
        return False
    
    def _has_sufficient_history(self, mac: str) -> bool:
        """检查设备是否有足够的历史数据
        
        Args:
            mac: 设备MAC地址
            
        Returns:
            是否有足够的历史数据
        """
        try:
            behaviors = self.database.get_device_behaviors(mac, days=7)
            return len(behaviors) >= self.min_observations
        except Exception as e:
            self.logger.error(f"检查历史数据失败: {str(e)}")
            return False
    
    def cleanup(self):
        """清理资源"""
        self.logger.info("清理设备行为分析器资源")
        
        # 清理过期的行为记录
        try:
            self.database.cleanup_old_behavior_records(self.learning_period_days)
        except Exception as e:
            self.logger.error(f"清理行为记录失败: {str(e)}")