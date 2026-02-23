#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ML风险增强器
将ML模型与现有风险评估系统集成，提供增强的风险判断能力
"""

import logging
from typing import Dict, List, Optional

from .factory import MLModelFactory
from .sklearn_risk_model import SklearnRiskModel


logger = logging.getLogger('LanSecurityMonitor')


class MLRiskEnhancer:
    """ML风险增强器"""
    
    def __init__(self, config, database=None):
        self.config = config
        self.database = database
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        self.enabled = config.get_bool('ENABLE_ML_RISK', True)
        self.model = None
        self.min_training_samples = config.get_int('ML_MIN_TRAINING_SAMPLES', 50)
        
        self._initialize()
    
    def _initialize(self):
        """初始化ML风险增强器"""
        if not self.enabled:
            self.logger.info("ML风险增强功能已禁用")
            return
        
        self.logger.info("初始化ML风险增强器...")
        
        self.model = MLModelFactory.create('risk_classifier', self.config, self.database)
        
        if self.model:
            model_loaded = self.model.load_model('risk_classifier.pkl')
            if model_loaded:
                self.logger.info("已加载已训练的风险评估模型")
            else:
                self.logger.info("将使用默认规则基础模型")
        else:
            self.logger.warning("无法创建ML模型，将使用规则基础方法")
    
    def initialize(self):
        """初始化（供外部调用）"""
        self.logger.info("ML风险增强器初始化完成")
        
        if self.enabled and self.database:
            self._check_and_train_model()
    
    def _check_and_train_model(self):
        """检查并训练模型"""
        training_data = self._prepare_training_data()
        
        if training_data and len(training_data) >= self.min_training_samples:
            self.logger.info(f"使用 {len(training_data)} 个样本训练ML模型...")
            success = self.model.train(training_data)
            if success:
                self.logger.info("ML模型训练完成")
            else:
                self.logger.warning("ML模型训练失败，将使用默认模型")
        else:
            sample_count = len(training_data) if training_data else 0
            self.logger.info(f"训练数据不足 ({sample_count}/{self.min_training_samples})，使用规则基础模型")
    
    def _prepare_training_data(self) -> List[Dict]:
        """准备训练数据"""
        if not self.database:
            return []
        
        try:
            devices = self.database.load_known_devices()
            
            training_data = []
            
            for mac, device in devices.items():
                base_result = self._get_base_risk_result(device)
                
                if base_result:
                    label = self._risk_score_to_label(base_result.get('risk_score', 50))
                    
                    training_data.append({
                        'data': {
                            **device,
                            'score_details': base_result.get('score_details', {}),
                            'weight_details': base_result.get('weight_details', {}),
                            'is_new': not device.get('is_known', False),
                            'historical_risk_avg': device.get('historical_risk_avg', 50)
                        },
                        'label': label
                    })
            
            return training_data
            
        except Exception as e:
            self.logger.error(f"准备训练数据失败: {e}")
            return []
    
    def _get_base_risk_result(self, device: Dict) -> Optional[Dict]:
        """获取基础风险评估结果"""
        from ..monitors.device_risk_analyzer import DeviceRiskAnalyzer
        
        analyzer = DeviceRiskAnalyzer(self.config, self.database)
        return analyzer.analyze_device_risk(device)
    
    def _risk_score_to_label(self, score: float) -> int:
        """将风险分数转换为标签"""
        if score >= 70:
            return 3
        elif score >= 55:
            return 2
        elif score >= 40:
            return 1
        else:
            return 0
    
    def enhance_risk_assessment(self, device: Dict, base_risk_result: Dict) -> Dict:
        """增强风险评估
        
        将ML模型的预测与基础风险评估结果融合
        
        Args:
            device: 设备信息
            base_risk_result: 基础风险评估结果
            
        Returns:
            增强后的风险评估结果
        """
        if not self.enabled or not self.model:
            return base_risk_result
        
        try:
            return self.model.enhance_risk_assessment(device, base_risk_result)
        except Exception as e:
            self.logger.error(f"ML增强失败: {e}")
            return base_risk_result
    
    def predict_risk(self, device: Dict) -> Dict:
        """直接预测设备风险
        
        Args:
            device: 设备信息
            
        Returns:
            预测结果
        """
        if not self.enabled or not self.model:
            return {
                'error': 'ML功能未启用'
            }
        
        try:
            from ..monitors.device_risk_analyzer import DeviceRiskAnalyzer
            
            analyzer = DeviceRiskAnalyzer(self.config, self.database)
            base_result = analyzer.analyze_device_risk(device)
            
            return self.enhance_risk_assessment(device, base_result)
            
        except Exception as e:
            self.logger.error(f"风险预测失败: {e}")
            return {'error': str(e)}
    
    def add_training_sample(self, device: Dict, actual_risk_level: str):
        """添加训练样本
        
        根据用户确认的风险等级添加训练样本
        
        Args:
            device: 设备信息
            actual_risk_level: 实际风险等级 (safe/low/medium/high/critical)
        """
        label_map = {
            'safe': 0,
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 3
        }
        
        label = label_map.get(actual_risk_level, 1)
        
        if self.database:
            self.database.save_ml_training_data(device, label)
        
        self.logger.info(f"已添加训练样本: 设备 {device.get('mac')}, 标签: {actual_risk_level}")
        
        self._check_and_train_model()
    
    def get_model_info(self) -> Dict:
        """获取模型信息"""
        info = {
            'enabled': self.enabled,
            'model_loaded': self.model is not None,
            'is_trained': False,
            'model_type': None,
            'feature_importance': None
        }
        
        if self.model:
            info['model_type'] = 'sklearn_risk_classifier'
            info['is_trained'] = self.model.is_trained
            
            if self.model.is_trained:
                info['feature_importance'] = self.model.get_feature_importance()
        
        return info
    
    def retrain_model(self) -> bool:
        """重新训练模型"""
        self.logger.info("开始重新训练ML模型...")
        
        self._check_and_train_model()
        
        return self.model and self.model.is_trained
    
    def export_model(self, filepath: str) -> bool:
        """导出模型"""
        if not self.model:
            return False
        
        return self.model.save_model(filepath)
    
    def import_model(self, filepath: str) -> bool:
        """导入模型"""
        if not self.model:
            self.model = SklearnRiskModel(self.config, self.database)
        
        return self.model.load_model(filepath)
