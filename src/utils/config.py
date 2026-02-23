#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置管理模块
"""

import os
import logging
from typing import Optional, Any


class Config:
    """配置管理类"""
    
    def __init__(self, config_file: str = 'config/config.env'):
        self.config_file = config_file
        self.logger = logging.getLogger('LanSecurityMonitor')
        self._config = {}
        self._load_config()
    
    def _load_config(self):
        """加载配置文件"""
        if not os.path.exists(self.config_file):
            self.logger.warning(f"配置文件不存在: {self.config_file}")
            return
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    
                    # 跳过注释和空行
                    if not line or line.startswith('#'):
                        continue
                    
                    # 解析键值对
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        # 移除引号
                        if value.startswith('"') and value.endswith('"'):
                            value = value[1:-1]
                        elif value.startswith("'") and value.endswith("'"):
                            value = value[1:-1]
                        
                        self._config[key] = value
        
        except Exception as e:
            self.logger.error(f"加载配置文件失败: {str(e)}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值"""
        # 优先从环境变量获取
        env_value = os.environ.get(key)
        if env_value is not None:
            return env_value
        
        # 从配置文件获取
        return self._config.get(key, default)
    
    def get_int(self, key: str, default: int = 0) -> int:
        """获取整数配置值"""
        value = self.get(key, default)
        try:
            return int(value)
        except (ValueError, TypeError):
            return default
    
    def get_float(self, key: str, default: float = 0.0) -> float:
        """获取浮点数配置值"""
        value = self.get(key, default)
        try:
            return float(value)
        except (ValueError, TypeError):
            return default
    
    def get_bool(self, key: str, default: bool = False) -> bool:
        """获取布尔配置值"""
        value = self.get(key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', 'yes', '1', 'on')
        return default
    
    def get_list(self, key: str, default: list = None) -> list:
        """获取列表配置值（逗号分隔）"""
        value = self.get(key, '')
        if not value:
            return default or []
        
        return [item.strip() for item in value.split(',') if item.strip()]
    
    def set(self, key: str, value: Any) -> bool:
        """设置配置值并保存到文件
        
        Args:
            key: 配置键
            value: 配置值
            
        Returns:
            是否保存成功
        """
        try:
            str_value = str(value)
            self._config[key] = str_value
            
            lines = []
            key_found = False
            
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        stripped = line.strip()
                        if stripped and not stripped.startswith('#') and '=' in stripped:
                            k, _ = stripped.split('=', 1)
                            if k.strip() == key:
                                lines.append(f'{key}="{str_value}"\n')
                                key_found = True
                            else:
                                lines.append(line)
                        else:
                            lines.append(line)
            
            if not key_found:
                lines.append(f'{key}="{str_value}"\n')
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            
            self.logger.info(f"配置已更新: {key}")
            return True
            
        except Exception as e:
            self.logger.error(f"保存配置失败: {str(e)}")
            return False
