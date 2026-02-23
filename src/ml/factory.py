#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ML模型工厂
使用工厂模式创建ML模型，便于扩展和替换
"""

import logging
from typing import Optional, Dict, Any

from .base import MLModelBase


logger = logging.getLogger('LanSecurityMonitor')


class MLModelFactory:
    """ML模型工厂类"""
    
    _registry: Dict[str, type] = {}
    
    @classmethod
    def register(cls, model_type: str, model_class: type):
        """注册ML模型类
        
        Args:
            model_type: 模型类型标识
            model_class: 模型类
        """
        cls._registry[model_type] = model_class
        logger.debug(f"已注册ML模型: {model_type}")
    
    @classmethod
    def create(cls, model_type: str, config, database=None) -> Optional[MLModelBase]:
        """创建ML模型实例
        
        Args:
            model_type: 模型类型
            config: 配置对象
            database: 数据库实例
            
        Returns:
            ML模型实例，如果类型不存在则返回None
        """
        if model_type not in cls._registry:
            logger.warning(f"未知的模型类型: {model_type}")
            return None
        
        model_class = cls._registry[model_type]
        return model_class(config, database)
    
    @classmethod
    def list_available_models(cls) -> list:
        """列出所有可用的模型类型
        
        Returns:
            模型类型列表
        """
        return list(cls._registry.keys())


def register_default_models():
    """注册默认的ML模型"""
    try:
        from .sklearn_risk_model import SklearnRiskModel
        from .sklearn_behavior_model import SklearnBehaviorModel
        
        MLModelFactory.register('risk_classifier', SklearnRiskModel)
        MLModelFactory.register('behavior_anomaly', SklearnBehaviorModel)
        
        logger.info("已注册默认scikit-learn模型")
    except ImportError as e:
        logger.warning(f"无法导入scikit-learn模型: {e}")
        logger.info("请安装scikit-learn: pip install scikit-learn")


register_default_models()
