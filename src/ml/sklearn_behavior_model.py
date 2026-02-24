#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基于scikit-learn的行为异常检测模型
使用Isolation Forest进行设备行为异常检测
"""

import logging
import numpy as np
from typing import Dict, Any, Optional, List
from datetime import datetime

from .base import MLModelBase


logger = logging.getLogger('LanSecurityMonitor')


class SklearnBehaviorModel(MLModelBase):
    """基于scikit-learn的行为异常检测模型"""
    
    FEATURE_NAMES = [
        'online_duration_variance',
        'connection_frequency',
        'typical_online_hours',
        'data_transfer_rate',
        'port_access_pattern',
        'network_activity_score',
        'time_since_last_seen',
        'session_duration'
    ]
    
    def __init__(self, config, database=None):
        super().__init__(config, database)
        self.contamination = config.get_float('ML_ANOMALY_CONTAMINATION', 0.1)
        self._init_sklearn()
    
    def _init_sklearn(self):
        """初始化scikit-learn"""
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
            
            self.IsolationForest = IsolationForest
            self.StandardScaler = StandardScaler
            self.scaler = StandardScaler()
            
            self.model = self.IsolationForest(
                n_estimators=100,
                contamination=self.contamination,
                random_state=42,
                n_jobs=-1
            )
            
            self._initialize_default_thresholds()
            
        except ImportError:
            logger.error("scikit-learn未安装，请运行: pip install scikit-learn")
            raise
    
    def _initialize_default_thresholds(self):
        """初始化默认阈值"""
        self.is_trained = False
        self.default_thresholds = {
            'online_duration': {'min': 0.5, 'max': 23},
            'connection_frequency': {'min': 1, 'max': 50},
            'data_rate': {'min': 0, 'max': 1000},
            'port_access': {'min': 0, 'max': 20}
        }
    
    def _get_model_config(self) -> Dict:
        """获取模型配置"""
        return {
            'type': 'sklearn_behavior_anomaly',
            'algorithm': 'IsolationForest',
            'feature_names': self.FEATURE_NAMES,
            'contamination': self.contamination,
            'n_estimators': 100
        }
    
    def extract_features(self, data: Dict) -> Dict:
        """从行为数据提取特征
        
        Args:
            data: 设备行为数据字典
            
        Returns:
            特征字典
        """
        features = {}
        
        behavior_history = data.get('behavior_history', [])
        
        if behavior_history:
            online_durations = [b.get('online_duration_hours', 0) for b in behavior_history]
            features['online_duration_variance'] = float(np.var(online_durations)) if len(online_durations) > 1 else 0.0
            
            features['connection_frequency'] = len(behavior_history)
            
            online_hours = [b.get('online_hour', 12) for b in behavior_history]
            features['typical_online_hours'] = float(np.std(online_hours)) if len(online_hours) > 1 else 0.0
            
            data_rates = [b.get('data_rate_mbph', 0) for b in behavior_history]
            features['data_transfer_rate'] = float(np.mean(data_rates)) if data_rates else 0.0
            
            port_access = [b.get('unique_ports', 0) for b in behavior_history]
            features['port_access_pattern'] = float(np.std(port_access)) if len(port_access) > 1 else 0.0
        else:
            features['online_duration_variance'] = 0.0
            features['connection_frequency'] = 1
            features['typical_online_hours'] = 0.0
            features['data_transfer_rate'] = 0.0
            features['port_access_pattern'] = 0.0
        
        features['network_activity_score'] = min(data.get('network_activity_score', 50), 100)
        
        last_seen = data.get('last_seen_timestamp')
        if last_seen:
            try:
                if isinstance(last_seen, str):
                    last_time = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                else:
                    last_time = last_seen
                
                hours_since = (datetime.now() - last_time).total_seconds() / 3600
                features['time_since_last_seen'] = min(hours_since, 168)
            except:
                features['time_since_last_seen'] = 24
        else:
            features['time_since_last_seen'] = 24
        
        features['session_duration'] = data.get('session_duration_hours', 0)
        
        return features
    
    def _features_to_array(self, features: Dict) -> np.ndarray:
        """将特征字典转换为numpy数组"""
        values = []
        for name in self.FEATURE_NAMES:
            val = features.get(name, 0)
            if np.isnan(val) or np.isinf(val):
                val = 0
            values.append(val)
        return np.array(values).reshape(1, -1)
    
    def train(self, training_data: List[Dict]) -> bool:
        """训练模型
        
        Args:
            training_data: 训练数据列表，每个元素包含 'data' 和 'label'
            
        Returns:
            训练是否成功
        """
        if not training_data or len(training_data) < 20:
            self.logger.warning("行为分析训练数据不足，使用默认模型")
            return False
        
        try:
            X = []
            
            for item in training_data:
                features = self.extract_features(item['data'])
                X.append([features.get(name, 0) for name in self.FEATURE_NAMES])
            
            X = np.array(X)
            
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            
            X_scaled = self.scaler.fit_transform(X)
            
            self.model.fit(X_scaled)
            
            self.is_trained = True
            
            self.logger.info(f"行为异常检测模型训练完成，使用 {len(training_data)} 个样本")
            
            self.save_model('behavior_anomaly.pkl')
            
            if self.database:
                from datetime import datetime
                try:
                    self.database.save_ml_model_metadata(
                        model_type='behavior_anomaly',
                        trained_at=datetime.now().isoformat(),
                        training_samples=len(training_data),
                        accuracy=None,
                        config={'model_type': 'sklearn_if', 'n_features': len(self.FEATURE_NAMES)}
                    )
                except Exception as e:
                    self.logger.warning(f"保存模型元数据失败: {e}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"模型训练失败: {e}")
            return False
    
    def predict(self, features: Dict) -> Dict:
        """检测行为异常
        
        Args:
            features: 特征字典
            
        Returns:
            预测结果，包含 is_anomaly, anomaly_score, details
        """
        if not self.is_trained:
            return self._rule_based_predict(features)
        
        try:
            X = self._features_to_array(features)
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            X_scaled = self.scaler.transform(X)
            
            prediction = self.model.predict(X_scaled)[0]
            anomaly_score = self.model.score_samples(X_scaled)[0]
            
            is_anomaly = prediction == -1
            
            normalized_score = self._normalize_anomaly_score(anomaly_score)
            
            details = self._analyze_anomaly_details(features, is_anomaly, normalized_score)
            
            return {
                'is_anomaly': is_anomaly,
                'anomaly_score': round(normalized_score, 3),
                'raw_score': float(anomaly_score),
                'details': details,
                'model_used': 'sklearn_if'
            }
            
        except Exception as e:
            self.logger.error(f"异常检测失败，回退到规则基础方法: {e}")
            return self._rule_based_predict(features)
    
    def _normalize_anomaly_score(self, raw_score: float) -> float:
        """将原始异常分数归一化到0-100"""
        normalized = (raw_score + 1) / 2 * 100
        return max(0, min(100, normalized))
    
    def _rule_based_predict(self, features: Dict) -> Dict:
        """基于规则的异常检测（后备方法）"""
        anomaly_indicators = 0
        
        if features.get('online_duration_variance', 0) > 50:
            anomaly_indicators += 1
        
        if features.get('connection_frequency', 1) > 30:
            anomaly_indicators += 1
        
        if features.get('typical_online_hours', 0) > 8:
            anomaly_indicators += 1
        
        if features.get('port_access_pattern', 0) > 10:
            anomaly_indicators += 1
        
        if features.get('time_since_last_seen', 24) > 72:
            anomaly_indicators += 1
        
        is_anomaly = anomaly_indicators >= 2
        
        anomaly_score = min(anomaly_indicators * 20, 100)
        
        details = self._analyze_anomaly_details(features, is_anomaly, anomaly_score)
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': anomaly_score,
            'details': details,
            'model_used': 'rule_based'
        }
    
    def _analyze_anomaly_details(self, features: Dict, is_anomaly: bool, score: float) -> List[str]:
        """分析异常详情"""
        details = []
        
        if is_anomaly:
            details.append("检测到行为异常")
        
        if features.get('online_duration_variance', 0) > 30:
            details.append("在线时长波动较大")
        
        if features.get('connection_frequency', 0) > 20:
            details.append("连接频率异常")
        
        if features.get('typical_online_hours', 0) > 6:
            details.append("上线时间段异常")
        
        if features.get('data_transfer_rate', 0) > 500:
            details.append("数据传输率较高")
        
        if features.get('port_access_pattern', 0) > 8:
            details.append("端口访问模式异常")
        
        if features.get('time_since_last_seen', 0) > 48:
            details.append("长时间未活动后突然出现")
        
        if not details:
            details.append("行为正常")
        
        return details
    
    def detect_anomaly(self, device: Dict, behavior_data: Dict) -> Dict:
        """检测设备行为异常
        
        使用ML模型检测设备行为是否异常
        
        Args:
            device: 设备信息
            behavior_data: 行为数据
            
        Returns:
            异常检测结果
        """
        combined_data = {**device, **behavior_data}
        
        features = self.extract_features(combined_data)
        
        prediction = self.predict(features)
        
        return {
            'device_mac': device.get('mac'),
            'device_ip': device.get('ip'),
            'is_anomaly': prediction.get('is_anomaly', False),
            'anomaly_score': prediction.get('anomaly_score', 0),
            'details': prediction.get('details', []),
            'model_source': prediction.get('model_used', 'unknown'),
            'confidence': prediction.get('confidence', 0.5),
            'features': features
        }
    
    def get_feature_importance(self) -> Optional[Dict]:
        """获取特征重要性"""
        return None
    
    def update_model_with_feedback(self, device_mac: str, actual_label: int) -> bool:
        """根据用户反馈更新模型
        
        Args:
            device_mac: 设备MAC地址
            actual_label: 实际标签 (0=正常, 1=异常)
            
        Returns:
            更新是否成功
        """
        self.logger.info(f"收到用户反馈: 设备 {device_mac}, 标签: {actual_label}")
        
        if self.database:
            self.database.save_ml_feedback(device_mac, actual_label)
        
        return True
