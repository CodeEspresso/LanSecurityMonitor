#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置管理模块
"""

import os
import logging
import re
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
    
    ALLOWLIST_KEYS = ['NAS_DEVICES', 'TRUSTED_EXTERNAL_IPS', 'TRUSTED_NAS_PORTS']
    DENYLIST_KEYS = [
        'WEB_PASSWORD', 'WEB_SECRET_KEY', 'BARK_API_KEY', 'BARK_DEVICE_TOKEN',
        'IKUAI_USERNAME', 'IKUAI_PASSWORD', 'ML_MODEL_PATH', 'DATABASE_PATH',
        'SECRET', 'TOKEN', 'KEY', 'PASSWORD'
    ]
    
    @staticmethod
    def validate_mac(mac: str) -> bool:
        """验证MAC地址格式"""
        pattern = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
        return bool(pattern.match(mac))
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """验证IP地址格式"""
        pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if not pattern.match(ip):
            return False
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    
    def set(self, key: str, value: Any, allowlist: list = None) -> bool:
        """设置配置值并保存到文件
        
        Args:
            key: 配置键
            value: 配置值
            allowlist: 自定义允许的键列表（可选）
            
        Returns:
            是否保存成功
        """
        allowed_keys = allowlist or self.ALLOWLIST_KEYS
        
        if key not in allowed_keys:
            self.logger.warning(f"拒绝写入未授权的配置键: {key}")
            return False
        
        if any(deny_key in key.upper() for deny_key in self.DENYLIST_KEYS):
            self.logger.warning(f"拒绝写入敏感配置键: {key}")
            return False
        
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
