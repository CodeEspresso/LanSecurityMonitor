#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基于scikit-learn的风险评估模型
使用随机森林分类器进行设备风险分类
"""

import logging
import numpy as np
from typing import Dict, Any, Optional, List

from .base import MLModelBase


logger = logging.getLogger('LanSecurityMonitor')


class SklearnRiskModel(MLModelBase):
    """基于scikit-learn的风险评估模型"""
    
    FEATURE_NAMES = [
        'vendor_score',
        'device_type_score', 
        'ip_pattern_score',
        'mac_pattern_score',
        'network_role_score',
        'is_new_device',
        'port_count',
        'connection_time_score',
        'historical_risk_avg'
    ]
    
    def __init__(self, config, database=None):
        super().__init__(config, database)
        self._init_sklearn()
    
    def _init_sklearn(self):
        """初始化scikit-learn"""
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.preprocessing import StandardScaler
            
            self.RFClassifier = RandomForestClassifier
            self.StandardScaler = StandardScaler
            self.scaler = StandardScaler()
            
            self.model = self.RFClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )
            
            self._initialize_default_model()
            
        except ImportError:
            logger.error("scikit-learn未安装，请运行: pip install scikit-learn")
            raise
    
    def _initialize_default_model(self):
        """初始化默认模型（使用规则基础的预测）"""
        self.is_trained = False
        self.default_weights = {
            'vendor_score': 2.5,
            'device_type_score': 1.5,
            'ip_pattern_score': 1.5,
            'mac_pattern_score': 1.0,
            'network_role_score': 1.0,
            'is_new_device': 2.0,
            'port_count': 1.0,
            'connection_time_score': 1.0,
            'historical_risk_avg': 1.5
        }
    
    def _get_model_config(self) -> Dict:
        """获取模型配置"""
        return {
            'type': 'sklearn_risk_classifier',
            'algorithm': 'RandomForestClassifier',
            'feature_names': self.FEATURE_NAMES,
            'n_estimators': 100,
            'max_depth': 10
        }
    
    def extract_features(self, data: Dict) -> Dict:
        """从设备数据提取特征
        
        Args:
            data: 设备数据字典
            
        Returns:
            特征字典
        """
        features = {}
        
        score_details = data.get('score_details', {})
        weights = data.get('weight_details', {})
        
        features['vendor_score'] = score_details.get('vendor', 50)
        features['device_type_score'] = score_details.get('device_type', 50)
        features['ip_pattern_score'] = score_details.get('ip_pattern', 50)
        features['mac_pattern_score'] = score_details.get('mac_pattern', 50)
        features['network_role_score'] = score_details.get('network_role', 50)
        
        features['is_new_device'] = 1 if data.get('is_new', True) else 0
        
        features['port_count'] = min(data.get('open_ports', []).__len__(), 10)
        
        connection_time = data.get('connection_duration_hours', 0)
        if connection_time < 1:
            features['connection_time_score'] = 80
        elif connection_time < 24:
            features['connection_time_score'] = 60
        elif connection_time < 168:
            features['connection_time_score'] = 40
        else:
            features['connection_time_score'] = 20
        
        features['historical_risk_avg'] = data.get('historical_risk_avg', 50)
        
        return features
    
    def _features_to_array(self, features: Dict) -> np.ndarray:
        """将特征字典转换为numpy数组"""
        values = []
        for name in self.FEATURE_NAMES:
            values.append(features.get(name, 0))
        return np.array(values).reshape(1, -1)
    
    def train(self, training_data: List[Dict]) -> bool:
        """训练模型
        
        Args:
            training_data: 训练数据列表，每个元素包含 'data' 和 'label'
            
        Returns:
            训练是否成功
        """
        if not training_data or len(training_data) < 10:
            self.logger.warning("训练数据不足，使用默认模型")
            return False
        
        try:
            X = []
            y = []
            
            for item in training_data:
                features = self.extract_features(item['data'])
                X.append([features.get(name, 0) for name in self.FEATURE_NAMES])
                y.append(item['label'])
            
            X = np.array(X)
            y = np.array(y)
            
            X_scaled = self.scaler.fit_transform(X)
            
            self.model.fit(X_scaled, y)
            
            self.is_trained = True
            
            self.logger.info(f"模型训练完成，使用 {len(training_data)} 个样本")
            
            self.save_model('risk_classifier.pkl')
            
            if self.database:
                import json
                from datetime import datetime
                try:
                    accuracy = self.model.score(X_scaled, y) if hasattr(self.model, 'score') else None
                    self.database.save_ml_model_metadata(
                        model_type='risk_classifier',
                        trained_at=datetime.now().isoformat(),
                        training_samples=len(training_data),
                        accuracy=accuracy,
                        config={'model_type': 'sklearn_rf', 'n_features': len(self.FEATURE_NAMES)}
                    )
                except Exception as e:
                    self.logger.warning(f"保存模型元数据失败: {e}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"模型训练失败: {e}")
            return False
    
    def predict(self, features: Dict) -> Dict:
        """预测设备风险等级
        
        Args:
            features: 特征字典
            
        Returns:
            预测结果，包含 prediction, confidence, risk_factors
        """
        if not self.is_trained:
            return self._rule_based_predict(features)
        
        try:
            X = self._features_to_array(features)
            X_scaled = self.scaler.transform(X)
            
            prediction = self.model.predict(X_scaled)[0]
            probabilities = self.model.predict_proba(X_scaled)[0]
            confidence = float(max(probabilities))
            
            risk_factors = self._analyze_risk_factors(features)
            
            return {
                'prediction': int(prediction),
                'confidence': confidence,
                'risk_factors': risk_factors,
                'model_used': 'sklearn_rf'
            }
            
        except Exception as e:
            self.logger.error(f"预测失败，回退到规则基础预测: {e}")
            return self._rule_based_predict(features)
    
    def _rule_based_predict(self, features: Dict) -> Dict:
        """基于规则的预测（后备方法）"""
        weights = self.default_weights
        total_weight = sum(weights.values())
        
        weighted_score = sum(
            features.get(name, 50) * weights.get(name, 1) 
            for name in self.FEATURE_NAMES
        ) / total_weight
        
        if weighted_score >= 70:
            prediction = 3
            risk_level = 'critical'
        elif weighted_score >= 55:
            prediction = 2
            risk_level = 'high'
        elif weighted_score >= 40:
            prediction = 1
            risk_level = 'medium'
        else:
            prediction = 0
            risk_level = 'low'
        
        risk_factors = self._analyze_risk_factors(features)
        
        return {
            'prediction': prediction,
            'confidence': 0.5,
            'risk_level': risk_level,
            'weighted_score': round(weighted_score, 2),
            'risk_factors': risk_factors,
            'model_used': 'rule_based'
        }
    
    def _analyze_risk_factors(self, features: Dict) -> List[str]:
        """分析风险因素"""
        factors = []
        
        if features.get('vendor_score', 0) >= 60:
            factors.append('厂商不在信任列表')
        
        if features.get('device_type_score', 0) >= 60:
            factors.append('设备类型未知或不常见')
        
        if features.get('ip_pattern_score', 0) >= 70:
            factors.append('IP地址段异常')
        
        if features.get('is_new_device', 0) == 1:
            factors.append('新设备首次接入')
        
        if features.get('port_count', 0) >= 5:
            factors.append('开放端口较多')
        
        if features.get('connection_time_score', 0) >= 70:
            factors.append('连接时间较短')
        
        if features.get('historical_risk_avg', 50) >= 60:
            factors.append('历史风险评分较高')
        
        return factors
    
    def get_feature_importance(self) -> Optional[Dict]:
        """获取特征重要性"""
        if not self.is_trained:
            return None
        
        try:
            importances = self.model.feature_importances_
            return {
                name: float(imp) 
                for name, imp in zip(self.FEATURE_NAMES, importances)
            }
        except Exception as e:
            self.logger.error(f"获取特征重要性失败: {e}")
            return None
    
    def enhance_risk_assessment(self, device: Dict, base_risk_result: Dict) -> Dict:
        """增强风险评估
        
        使用ML模型对基础风险评估结果进行增强
        
        Args:
            device: 设备信息
            base_risk_result: 基础风险评估结果
            
        Returns:
            增强后的风险评估结果
        """
        features = self.extract_features(device)
        
        ml_prediction = self.predict(features)
        
        base_score = base_risk_result.get('risk_score', 50)
        
        if ml_prediction.get('model_used') == 'sklearn_rf':
            ml_confidence = ml_prediction.get('confidence', 0)
            
            confidence_weight = min(ml_confidence, 0.7)
            
            ml_score = self._prediction_to_score(ml_prediction.get('prediction', 1))
            
            enhanced_score = base_score * (1 - confidence_weight) + ml_score * confidence_weight
        else:
            enhanced_score = base_score
        
        enhanced_score = round(enhanced_score, 1)
        
        risk_level = self._determine_risk_level(enhanced_score)
        
        all_risk_factors = list(set(
            base_risk_result.get('score_details', {}).keys() + 
            ml_prediction.get('risk_factors', [])
        ))
        
        return {
            **base_risk_result,
            'ml_enhanced': True,
            'ml_prediction': ml_prediction,
            'enhanced_score': enhanced_score,
            'risk_level': risk_level,
            'all_risk_factors': all_risk_factors,
            'confidence': ml_prediction.get('confidence', 0.5),
            'model_source': ml_prediction.get('model_used', 'unknown')
        }
    
    def _prediction_to_score(self, prediction: int) -> float:
        """将预测类别转换为分数"""
        mapping = {0: 20, 1: 40, 2: 70, 3: 90}
        return mapping.get(prediction, 50)
    
    def _determine_risk_level(self, score: float) -> str:
        """确定风险等级"""
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
