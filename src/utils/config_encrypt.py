#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置文件加密工具模块
支持配置文件的加密和解密
"""

import os
import json
import base64
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Optional

logger = logging.getLogger('LanSecurityMonitor')


class ConfigEncryptor:
    """配置文件加密类"""
    
    def __init__(self, password: Optional[str] = None, salt: Optional[bytes] = None):
        """
        Args:
            password: 加密密码
            salt: 盐值（可选）
        """
        self.password = password or os.environ.get('CONFIG_ENCRYPT_PASSWORD')
        self.salt = salt or os.environ.get('CONFIG_ENCRYPT_SALT', 'lan_security_monitor_salt').encode()
        self.logger = logging.getLogger('LanSecurityMonitor')
        self._fernet = None
        
        if self.password:
            self._initialize_fernet()
    
    def _initialize_fernet(self):
        """初始化Fernet加密器"""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.password.encode()))
            self._fernet = Fernet(key)
        except Exception as e:
            self.logger.error(f"初始化加密器失败: {str(e)}")
            self._fernet = None
    
    def encrypt_file(self, input_file: str, output_file: str) -> bool:
        """加密配置文件
        
        Args:
            input_file: 输入文件路径
            output_file: 输出文件路径
            
        Returns:
            bool: 是否成功
        """
        if not self._fernet:
            self.logger.error("加密器未初始化，需要设置密码")
            return False
        
        try:
            if not os.path.exists(input_file):
                self.logger.error(f"输入文件不存在: {input_file}")
                return False
            
            # 读取文件内容
            with open(input_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 加密内容
            encrypted_content = self._fernet.encrypt(content.encode())
            
            # 写入加密文件
            with open(output_file, 'wb') as f:
                f.write(encrypted_content)
            
            self.logger.info(f"配置文件已加密: {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"加密文件失败: {str(e)}")
            return False
    
    def decrypt_file(self, input_file: str, output_file: str) -> bool:
        """解密配置文件
        
        Args:
            input_file: 输入文件路径
            output_file: 输出文件路径
            
        Returns:
            bool: 是否成功
        """
        if not self._fernet:
            self.logger.error("加密器未初始化，需要设置密码")
            return False
        
        try:
            if not os.path.exists(input_file):
                self.logger.error(f"输入文件不存在: {input_file}")
                return False
            
            # 读取加密内容
            with open(input_file, 'rb') as f:
                encrypted_content = f.read()
            
            # 解密内容
            decrypted_content = self._fernet.decrypt(encrypted_content).decode()
            
            # 写入解密文件
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(decrypted_content)
            
            self.logger.info(f"配置文件已解密: {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"解密文件失败: {str(e)}")
            return False
    
    def encrypt_string(self, text: str) -> Optional[str]:
        """加密字符串
        
        Args:
            text: 要加密的文本
            
        Returns:
            Optional[str]: 加密后的字符串
        """
        if not self._fernet:
            return None
        
        try:
            encrypted = self._fernet.encrypt(text.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            self.logger.error(f"加密字符串失败: {str(e)}")
            return None
    
    def decrypt_string(self, encrypted_text: str) -> Optional[str]:
        """解密字符串
        
        Args:
            encrypted_text: 加密的文本
            
        Returns:
            Optional[str]: 解密后的字符串
        """
        if not self._fernet:
            return None
        
        try:
            encrypted_bytes = base64.b64decode(encrypted_text.encode())
            decrypted = self._fernet.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            self.logger.error(f"解密字符串失败: {str(e)}")
            return None
    
    def is_encrypted(self, file_path: str) -> bool:
        """检查文件是否已加密
        
        Args:
            file_path: 文件路径
            
        Returns:
            bool: 是否加密
        """
        try:
            if not os.path.exists(file_path):
                return False
            
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # 尝试解密，如果成功则是加密文件
            if self._fernet:
                try:
                    self._fernet.decrypt(content)
                    return True
                except:
                    return False
            
            return False
            
        except Exception:
            return False


def encrypt_config():
    """加密配置文件的命令行工具"""
    import argparse
    
    parser = argparse.ArgumentParser(description='加密配置文件')
    parser.add_argument('--input', '-i', required=True, help='输入文件路径')
    parser.add_argument('--output', '-o', required=True, help='输出文件路径')
    parser.add_argument('--password', '-p', help='加密密码')
    parser.add_argument('--salt', '-s', help='盐值')
    
    args = parser.parse_args()
    
    password = args.password or os.environ.get('CONFIG_ENCRYPT_PASSWORD')
    if not password:
        print('错误: 请提供加密密码或设置 CONFIG_ENCRYPT_PASSWORD 环境变量')
        return
    
    encryptor = ConfigEncryptor(password, args.salt.encode() if args.salt else None)
    success = encryptor.encrypt_file(args.input, args.output)
    
    if success:
        print(f"✅ 配置文件已加密: {args.output}")
    else:
        print("❌ 加密失败")


def decrypt_config():
    """解密配置文件的命令行工具"""
    import argparse
    
    parser = argparse.ArgumentParser(description='解密配置文件')
    parser.add_argument('--input', '-i', required=True, help='输入文件路径')
    parser.add_argument('--output', '-o', required=True, help='输出文件路径')
    parser.add_argument('--password', '-p', help='加密密码')
    parser.add_argument('--salt', '-s', help='盐值')
    
    args = parser.parse_args()
    
    password = args.password or os.environ.get('CONFIG_ENCRYPT_PASSWORD')
    if not password:
        print('错误: 请提供加密密码或设置 CONFIG_ENCRYPT_PASSWORD 环境变量')
        return
    
    encryptor = ConfigEncryptor(password, args.salt.encode() if args.salt else None)
    success = encryptor.decrypt_file(args.input, args.output)
    
    if success:
        print(f"✅ 配置文件已解密: {args.output}")
    else:
        print("❌ 解密失败")


if __name__ == '__main__':
    # 示例用法
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == 'encrypt':
            encrypt_config()
        elif sys.argv[1] == 'decrypt':
            decrypt_config()
        else:
            print('用法: python config_encrypt.py [encrypt|decrypt]')
    else:
        print('用法: python config_encrypt.py [encrypt|decrypt]')