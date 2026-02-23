#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全配置管理模块
支持从环境变量读取敏感信息，避免明文存储
支持加密配置文件
"""

import os
import logging
from typing import Optional, Any, Dict

# 尝试导入加密模块，不存在时不影响基础功能
try:
    from .config_encrypt import ConfigEncryptor
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    logger.warning("cryptography库未安装，配置文件加密功能将不可用")
    ConfigEncryptor = None
    CRYPTOGRAPHY_AVAILABLE = False

logger = logging.getLogger('LanSecurityMonitor')


class SecureConfig:
    """安全配置管理类"""
    
    def __init__(self, config_file: str = 'config/config.env'):
        self.config_file = config_file
        self.logger = logging.getLogger('LanSecurityMonitor')
        self._config = {}
        self._encryptor = None
        self._initialize_encryptor()
        self._load_config()
    
    def _initialize_encryptor(self):
        """初始化加密器"""
        if not CRYPTOGRAPHY_AVAILABLE:
            self.logger.debug("cryptography库未安装，跳过加密器初始化")
            self._encryptor = None
            return
        
        password = os.environ.get('CONFIG_ENCRYPT_PASSWORD')
        if password:
            self.logger.info("初始化配置文件加密器")
            self._encryptor = ConfigEncryptor(password)
        else:
            self.logger.debug("未设置配置文件加密密码，使用明文配置")
            self._encryptor = None
    
    def _load_config(self):
        """加载配置文件"""
        if not os.path.exists(self.config_file):
            self.logger.warning(f"配置文件不存在: {self.config_file}")
            return
        
        try:
            # 检查是否为加密文件（仅在加密库可用时）
            if CRYPTOGRAPHY_AVAILABLE and self._encryptor and hasattr(self._encryptor, 'is_encrypted') and self._encryptor.is_encrypted(self.config_file):
                self.logger.info(f"加载加密配置文件: {self.config_file}")
                
                # 解密配置内容
                with open(self.config_file, 'rb') as f:
                    encrypted_content = f.read()
                
                decrypted_content = self._encryptor._fernet.decrypt(encrypted_content).decode()
                
                # 解析解密后的内容
                for line in decrypted_content.split('\n'):
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
            else:
                # 加载明文配置文件
                self.logger.debug(f"加载明文配置文件: {self.config_file}")
                
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
    
    def get(self, key: str, default: Any = None, sensitive: bool = False) -> Any:
        """获取配置值
        
        Args:
            key: 配置键
            default: 默认值
            sensitive: 是否为敏感信息（优先从环境变量读取）
            
        Returns:
            配置值
        """
        # 敏感信息优先从环境变量读取
        if sensitive:
            env_value = os.environ.get(key)
            if env_value is not None:
                return env_value
            
            # 如果环境变量中有带前缀的版本，也使用
            env_key_with_prefix = f"LAN_SECURITY_{key}"
            env_value_with_prefix = os.environ.get(env_key_with_prefix)
            if env_value_with_prefix is not None:
                return env_value_with_prefix
        
        # 从配置文件获取
        return self._config.get(key, default)
    
    def get_int(self, key: str, default: int = 0, sensitive: bool = False) -> int:
        """获取整数配置值"""
        value = self.get(key, default, sensitive)
        try:
            return int(value)
        except (ValueError, TypeError):
            return default
    
    def get_bool(self, key: str, default: bool = False, sensitive: bool = False) -> bool:
        """获取布尔配置值"""
        value = self.get(key, default, sensitive)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', 'yes', '1', 'on')
        return default
    
    def get_list(self, key: str, default: list = None, sensitive: bool = False) -> list:
        """获取列表配置值（逗号分隔）"""
        value = self.get(key, '', sensitive)
        if not value:
            return default or []
        
        return [item.strip() for item in value.split(',') if item.strip()]
    
    def is_sensitive_configured(self, *keys: str) -> bool:
        """检查敏感配置是否已配置
        
        Args:
            *keys: 需要检查的配置键
            
        Returns:
            是否所有敏感配置都已配置
        """
        for key in keys:
            # 检查环境变量
            if os.environ.get(key) or os.environ.get(f"LAN_SECURITY_{key}"):
                continue
            
            # 检查配置文件（但警告这是不安全的）
            if key in self._config and self._config[key]:
                self.logger.warning(f"敏感配置 {key} 在配置文件中明文存储，建议使用环境变量")
                return False
            
            return False
        
        return True
    
    def get_security_status(self) -> Dict[str, Any]:
        """获取安全状态
        
        Returns:
            安全状态字典
        """
        sensitive_keys = [
            'BARK_KEY',
            'IKUAI_PASSWORD',
            'DB_PASSWORD',
            'ROUTER_PASSWORD'
        ]
        
        status = {
            'sensitive_keys': sensitive_keys,
            'configured_via_env': [],
            'configured_via_file': [],
            'security_level': 'unknown'
        }
        
        for key in sensitive_keys:
            # 检查环境变量
            if os.environ.get(key) or os.environ.get(f"LAN_SECURITY_{key}"):
                status['configured_via_env'].append(key)
            # 检查配置文件
            elif key in self._config and self._config[key]:
                status['configured_via_file'].append(key)
        
        # 计算安全等级
        if not status['configured_via_file']:
            status['security_level'] = 'high'
        elif len(status['configured_via_env']) > len(status['configured_via_file']):
            status['security_level'] = 'medium'
        else:
            status['security_level'] = 'low'
        
        return status