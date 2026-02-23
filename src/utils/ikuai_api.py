#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
爱快路由器API模块
"""

import logging
import requests
import hashlib
from typing import Dict, List, Optional

logger = logging.getLogger('LanSecurityMonitor')


class IKuaiAPI:
    """爱快路由器API类"""
    
    def __init__(self, config, secure_config=None):
        self.config = config
        self.secure_config = secure_config
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        # 配置项
        self.ikuai_url = config.get('IKUAI_URL', 'http://192.168.1.1')
        self.ikuai_port = config.get_int('IKUAI_PORT', 80)
        self.ikuai_username = config.get('IKUAI_USERNAME', 'admin')
        
        # 密码从环境变量读取（安全）
        if secure_config:
            self.ikuai_password = secure_config.get('IKUAI_PASSWORD', '', sensitive=True)
        else:
            self.ikuai_password = config.get('IKUAI_PASSWORD', '', sensitive=True)
        
        self.session = None
        self.session_id = None
    
    def initialize(self):
        """初始化API连接"""
        if not self.ikuai_password:
            self.logger.warning("爱快路由器密码未配置，跳过API集成")
            return False
        
        self.logger.info(f"初始化爱快路由器API: {self.ikuai_url}:{self.ikuai_port}")
        
        # 登录
        return self._login()
    
    def _login(self) -> bool:
        """登录爱快路由器"""
        try:
            # 爱快路由器API地址
            url = f"{self.ikuai_url}:{self.ikuai_port}/Action/login"
            
            # 计算MD5密码
            password_md5 = hashlib.md5(self.ikuai_password.encode()).hexdigest()
            
            # 爱快路由器API需要JSON格式
            data = {
                'username': self.ikuai_username,
                'passwd': password_md5
            }
            
            headers = {
                'Content-Type': 'application/json'
            }
            
            # 禁用SSL证书验证（爱快路由器使用自签名证书）
            response = requests.post(url, json=data, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('Result') == 10000:
                    self.session_id = result.get('SessionID')
                    self.logger.info("爱快路由器登录成功")
                    return True
                else:
                    self.logger.error(f"爱快路由器登录失败: {result.get('ErrMsg', '未知错误')}")
                    return False
            else:
                self.logger.error(f"爱快路由器登录请求失败: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"爱快路由器登录异常: {str(e)}")
            return False
    
    def add_device_to_blacklist(self, mac: str, ip: str, reason: str = '') -> bool:
        """添加设备到黑名单
        
        Args:
            mac: 设备MAC地址
            ip: 设备IP地址
            reason: 封禁原因
            
        Returns:
            是否成功
        """
        if not self.session_id:
            self.logger.warning("未登录，无法添加黑名单")
            return False
        
        try:
            url = f"{self.ikuai_url}:{self.ikuai_port}/Action/call"
            
            # 爱快路由器的黑名单接口
            # 注意：具体接口参数需要根据爱快路由器版本调整
            data = {
                'func_name': 'blacklist',
                'action': 'add',
                'param': {
                    'mac': mac,
                    'ip': ip,
                    'comment': reason or '安全监控自动封禁',
                    'enable': 1
                },
                'SessionID': self.session_id
            }
            
            response = requests.post(url, json=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('Result') == 10000:
                    self.logger.info(f"设备已添加到黑名单: {mac} ({ip})")
                    return True
                else:
                    self.logger.error(f"添加黑名单失败: {result.get('ErrMsg', '未知错误')}")
                    return False
            else:
                self.logger.error(f"添加黑名单请求失败: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"添加黑名单异常: {str(e)}")
            return False
    
    def remove_device_from_blacklist(self, mac: str) -> bool:
        """从黑名单移除设备
        
        Args:
            mac: 设备MAC地址
            
        Returns:
            是否成功
        """
        if not self.session_id:
            self.logger.warning("未登录，无法移除黑名单")
            return False
        
        try:
            url = f"{self.ikuai_url}:{self.ikuai_port}/Action/call"
            
            data = {
                'func_name': 'blacklist',
                'action': 'del',
                'param': {
                    'mac': mac
                },
                'SessionID': self.session_id
            }
            
            response = requests.post(url, json=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('Result') == 10000:
                    self.logger.info(f"设备已从黑名单移除: {mac}")
                    return True
                else:
                    self.logger.error(f"移除黑名单失败: {result.get('ErrMsg', '未知错误')}")
                    return False
            else:
                self.logger.error(f"移除黑名单请求失败: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"移除黑名单异常: {str(e)}")
            return False
    
    def get_blacklist(self) -> List[Dict]:
        """获取黑名单列表
        
        Returns:
            黑名单设备列表
        """
        if not self.session_id:
            self.logger.warning("未登录，无法获取黑名单")
            return []
        
        try:
            url = f"{self.ikuai_url}:{self.ikuai_port}/Action/call"
            
            data = {
                'func_name': 'blacklist',
                'action': 'show',
                'param': {},
                'SessionID': self.session_id
            }
            
            response = requests.post(url, json=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('Result') == 10000:
                    return result.get('Data', [])
                else:
                    self.logger.error(f"获取黑名单失败: {result.get('ErrMsg', '未知错误')}")
                    return []
            else:
                self.logger.error(f"获取黑名单请求失败: HTTP {response.status_code}")
                return []
                
        except Exception as e:
            self.logger.error(f"获取黑名单异常: {str(e)}")
            return []
    
    def disconnect_device(self, mac: str) -> bool:
        """断开设备连接（临时封禁）
        
        Args:
            mac: 设备MAC地址
            
        Returns:
            是否成功
        """
        if not self.session_id:
            self.logger.warning("未登录，无法断开设备")
            return False
        
        try:
            url = f"{self.ikuai_url}:{self.ikuai_port}/Action/call"
            
            data = {
                'func_name': 'online_user',
                'action': 'disconnect',
                'param': {
                    'mac': mac
                },
                'SessionID': self.session_id
            }
            
            response = requests.post(url, json=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('Result') == 10000:
                    self.logger.info(f"设备已断开连接: {mac}")
                    return True
                else:
                    self.logger.error(f"断开设备失败: {result.get('ErrMsg', '未知错误')}")
                    return False
            else:
                self.logger.error(f"断开设备请求失败: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"断开设备异常: {str(e)}")
            return False
    
    def logout(self):
        """登出"""
        if self.session_id:
            try:
                url = f"{self.ikuai_url}:{self.ikuai_port}/Action/logout"
                data = {'SessionID': self.session_id}
                requests.post(url, data=data, timeout=5)
                self.session_id = None
                self.logger.info("爱快路由器已登出")
            except Exception as e:
                self.logger.error(f"登出异常: {str(e)}")
    
    def cleanup(self):
        """清理资源"""
        self.logout()