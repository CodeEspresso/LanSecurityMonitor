#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ML模型基类
定义所有ML模型的抽象接口，便于扩展和替换
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import pickle
import os


class MLModelBase(ABC):
    """ML模型基类 - 定义所有ML模型的通用接口"""
    
    def __init__(self, config, database=None):
        self.config = config
        self.database = database
        self.logger = logging.getLogger('LanSecurityMonitor')
        self.model = None
        self.is_trained = False
        self.model_path = None
        self._initialize_path()
    
    def _initialize_path(self):
        """初始化模型存储路径"""
        model_dir = self.config.get('ML_MODEL_DIR', 'data/ml_models')
        if not os.path.isabs(model_dir):
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            model_dir = os.path.join(base_dir, model_dir)
        
        os.makedirs(model_dir, exist_ok=True)
        self.model_path = model_dir
    
    @abstractmethod
    def train(self, training_data: list) -> bool:
        """训练模型
        
        Args:
            training_data: 训练数据列表
            
        Returns:
            训练是否成功
        """
        pass
    
    @abstractmethod
    def predict(self, features: Dict) -> Dict:
        """预测
        
        Args:
            features: 特征字典
            
        Returns:
            预测结果
        """
        pass
    
    @abstractmethod
    def extract_features(self, data: Dict) -> Dict:
        """从原始数据提取特征
        
        Args:
            data: 原始数据
            
        Returns:
            特征字典
        """
        pass
    
    def save_model(self, filename: str) -> bool:
        """保存模型到文件
        
        Args:
            filename: 文件名
            
        Returns:
            保存是否成功
        """
        if self.model is None:
            self.logger.warning("模型未训练，无法保存")
            return False
        
        try:
            filepath = os.path.join(self.model_path, filename)
            with open(filepath, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'is_trained': self.is_trained,
                    'config': self._get_model_config()
                }, f)
            self.logger.info(f"模型已保存至: {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"保存模型失败: {e}")
            return False
    
    def load_model(self, filename: str) -> bool:
        """从文件加载模型
        
        Args:
            filename: 文件名
            
        Returns:
            加载是否成功
        """
        try:
            filepath = os.path.join(self.model_path, filename)
            if not os.path.exists(filepath):
                self.logger.warning(f"模型文件不存在: {filepath}")
                return False
            
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
                self.model = data.get('model')
                self.is_trained = data.get('is_trained', False)
            
            self.logger.info(f"模型已加载: {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"加载模型失败: {e}")
            return False
    
    @abstractmethod
    def _get_model_config(self) -> Dict:
        """获取模型配置信息
        
        Returns:
            模型配置字典
        """
        pass
    
    @abstractmethod
    def get_feature_importance(self) -> Optional[Dict]:
        """获取特征重要性
        
        Returns:
            特征重要性字典，如果不支持则返回None
        """
        pass
    
    def evaluate(self, test_data: list) -> Dict:
        """评估模型性能
        
        Args:
            test_data: 测试数据列表
            
        Returns:
            评估结果字典
        """
        if not self.is_trained:
            return {'error': '模型未训练'}
        
        correct = 0
        total = len(test_data)
        
        for item in test_data:
            features = self.extract_features(item['data'])
            result = self.predict(features)
            
            if result.get('prediction') == item.get('label'):
                correct += 1
        
        accuracy = correct / total if total > 0 else 0
        
        return {
            'accuracy': accuracy,
            'total_samples': total,
            'correct_predictions': correct
        }
