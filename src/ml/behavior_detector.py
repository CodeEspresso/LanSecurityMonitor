#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ML行为异常检测器
使用ML模型检测设备的异常行为模式
"""

import logging
from typing import Dict, List, Optional

from .factory import MLModelFactory
from .sklearn_behavior_model import SklearnBehaviorModel


logger = logging.getLogger('LanSecurityMonitor')


class MLBehaviorDetector:
    """ML行为异常检测器"""
    
    def __init__(self, config, database=None):
        self.config = config
        self.database = database
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        self.enabled = config.get_bool('ENABLE_ML_BEHAVIOR', True)
        self.model = None
        self.min_training_samples = config.get_int('ML_BEHAVIOR_MIN_SAMPLES', 30)
        self.anomaly_threshold = config.get_float('ML_ANOMALY_THRESHOLD', 0.5)
        
        self._initialize()
    
    def _initialize(self):
        """初始化ML行为检测器"""
        if not self.enabled:
            self.logger.info("ML行为异常检测功能已禁用")
            return
        
        self.logger.info("初始化ML行为异常检测器...")
        
        self.model = MLModelFactory.create('behavior_anomaly', self.config, self.database)
        
        if self.model:
            model_loaded = self.model.load_model('behavior_anomaly.pkl')
            if model_loaded:
                self.logger.info("已加载已训练的行为异常检测模型")
            else:
                self.logger.info("将使用默认规则基础模型")
        else:
            self.logger.warning("无法创建ML行为模型，将使用规则基础方法")
    
    def initialize(self):
        """初始化（供外部调用）"""
        self.logger.info("ML行为异常检测器初始化完成")
        
        if self.enabled and self.database:
            self._check_and_train_model()
    
    def _check_and_train_model(self):
        """检查并训练模型"""
        training_data = self._prepare_training_data()
        
        if training_data and len(training_data) >= self.min_training_samples:
            self.logger.info(f"使用 {len(training_data)} 个样本训练行为异常检测模型...")
            success = self.model.train(training_data)
            if success:
                self.logger.info("行为异常检测模型训练完成")
            else:
                self.logger.warning("行为异常检测模型训练失败，将使用默认模型")
        else:
            sample_count = len(training_data) if training_data else 0
            self.logger.info(f"训练数据不足 ({sample_count}/{self.min_training_samples})，使用规则基础模型")
    
    def _prepare_training_data(self) -> List[Dict]:
        """准备训练数据"""
        if not self.database:
            return []
        
        try:
            behaviors = self.database.load_device_behaviors()
            
            training_data = []
            
            for mac, behavior_list in behaviors.items():
                if not behavior_list or len(behavior_list) < 5:
                    continue
                
                recent_behaviors = behavior_list[-50:]
                
                training_data.append({
                    'data': {
                        'behavior_history': recent_behaviors,
                        'network_activity_score': self._calculate_activity_score(recent_behaviors),
                        'session_duration_hours': self._calculate_avg_session_duration(recent_behaviors),
                        'last_seen_timestamp': behavior_list[-1].get('timestamp') if behavior_list else None
                    },
                    'label': 0
                })
            
            return training_data
            
        except Exception as e:
            self.logger.error(f"准备训练数据失败: {e}")
            return []
    
    def _calculate_activity_score(self, behaviors: List[Dict]) -> float:
        """计算活动评分"""
        if not behaviors:
            return 50.0
        
        online_counts = sum(1 for b in behaviors if b.get('is_online', False))
        return (online_counts / len(behaviors)) * 100
    
    def _calculate_avg_session_duration(self, behaviors: List[Dict]) -> float:
        """计算平均会话时长"""
        if not behaviors:
            return 0.0
        
        durations = [b.get('online_duration_hours', 0) for b in behaviors if b.get('online_duration_hours')]
        return sum(durations) / len(durations) if durations else 0.0
    
    def detect_anomaly(self, device: Dict, behavior_data: Dict) -> Dict:
        """检测设备行为异常
        
        Args:
            device: 设备信息
            behavior_data: 行为数据
            
        Returns:
            异常检测结果
        """
        if not self.enabled or not self.model:
            return {
                'device_mac': device.get('mac'),
                'is_anomaly': False,
                'anomaly_score': 0,
                'enabled': False
            }
        
        try:
            return self.model.detect_anomaly(device, behavior_data)
        except Exception as e:
            self.logger.error(f"行为异常检测失败: {e}")
            return {
                'device_mac': device.get('mac'),
                'is_anomaly': False,
                'anomaly_score': 0,
                'error': str(e)
            }
    
    def batch_detect(self, devices: List[Dict], behaviors: Dict[str, List[Dict]]) -> List[Dict]:
        """批量检测设备行为异常
        
        Args:
            devices: 设备列表
            behaviors: 行为数据字典 {mac: [behaviors]}
            
        Returns:
            异常检测结果列表
        """
        results = []
        
        for device in devices:
            mac = device.get('mac')
            device_behaviors = behaviors.get(mac, [])
            
            behavior_data = {
                'behavior_history': device_behaviors,
                'network_activity_score': self._calculate_activity_score(device_behaviors),
                'session_duration_hours': self._calculate_avg_session_duration(device_behaviors)
            }
            
            result = self.detect_anomaly(device, behavior_data)
            results.append(result)
        
        anomalies = [r for r in results if r.get('is_anomaly')]
        
        if anomalies:
            self.logger.warning(f"检测到 {len(anomalies)} 个设备存在行为异常")
        
        return results
    
    def add_feedback(self, device_mac: str, is_anomaly: bool):
        """添加用户反馈
        
        Args:
            device_mac: 设备MAC地址
            is_anomaly: 是否真的异常
        """
        if self.model and hasattr(self.model, 'update_model_with_feedback'):
            self.model.update_model_with_feedback(device_mac, 1 if is_anomaly else 0)
    
    def get_model_info(self) -> Dict:
        """获取模型信息"""
        info = {
            'enabled': self.enabled,
            'model_loaded': self.model is not None,
            'is_trained': False,
            'model_type': None,
            'anomaly_threshold': self.anomaly_threshold
        }
        
        if self.model:
            info['model_type'] = 'sklearn_behavior_anomaly'
            info['is_trained'] = self.model.is_trained
        
        return info
    
    def retrain_model(self) -> bool:
        """重新训练模型"""
        self.logger.info("开始重新训练行为异常检测模型...")
        
        self._check_and_train_model()
        
        return self.model and self.model.is_trained
    
    def get_device_behavior_profile(self, device_mac: str) -> Optional[Dict]:
        """获取设备行为画像
        
        Args:
            device_mac: 设备MAC地址
            
        Returns:
            行为画像字典
        """
        if not self.database:
            return None
        
        try:
            behaviors = self.database.load_device_behavior(device_mac)
            
            if not behaviors:
                return None
            
            recent = behaviors[-30:]
            
            online_hours = [b.get('online_hour', 12) for b in recent]
            
            data_rates = [b.get('data_rate_mbph', 0) for b in recent]
            
            return {
                'device_mac': device_mac,
                'total_observations': len(behaviors),
                'recent_observations': len(recent),
                'typical_online_hours': {
                    'mean': sum(online_hours) / len(online_hours) if online_hours else 0,
                    'std': (sum((h - sum(online_hours)/len(online_hours))**2 for h in online_hours) / len(online_hours))**0.5 if len(online_hours) > 1 else 0
                },
                'data_rate': {
                    'mean': sum(data_rates) / len(data_rates) if data_rates else 0,
                    'max': max(data_rates) if data_rates else 0
                },
                'online_pattern': self._analyze_online_pattern(recent)
            }
            
        except Exception as e:
            self.logger.error(f"获取设备行为画像失败: {e}")
            return None
    
    def _analyze_online_pattern(self, behaviors: List[Dict]) -> str:
        """分析在线模式"""
        if not behaviors:
            return 'unknown'
        
        online_count = sum(1 for b in behaviors if b.get('is_online', False))
        online_ratio = online_count / len(behaviors)
        
        if online_ratio > 0.8:
            return 'always_online'
        elif online_ratio > 0.5:
            return 'frequently_online'
        elif online_ratio > 0.2:
            return 'occasionally_online'
        else:
            return 'rarely_online'
