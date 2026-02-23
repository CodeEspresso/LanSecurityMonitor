#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
局域网安全监控系统
主入口文件
"""

import os
import sys
import time
import signal
import logging
import threading
from pathlib import Path

# 加载 .env 文件（必须在其他导入之前）
from dotenv import load_dotenv
load_dotenv()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.security_monitor import SecurityMonitor
from src.utils.config import Config
from src.utils.secure_config import SecureConfig
from src.utils.logger import setup_logger


class LanSecurityMonitor:
    """局域网安全监控主程序"""
    
    def __init__(self, config_file='config/config.env'):
        self.config = Config(config_file)
        self.secure_config = SecureConfig(config_file)
        self.logger = setup_logger(
            name='LanSecurityMonitor',
            log_level=self.config.get('LOG_LEVEL', 'INFO'),
            log_file='logs/monitor.log'
        )
        
        # 检查安全配置
        self._check_security()
        
        self.monitor = SecurityMonitor(self.config, self.secure_config)
        self.running = False
        self.web_thread = None
        
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _check_security(self):
        """检查安全配置"""
        security_status = self.secure_config.get_security_status()
        
        self.logger.info("=" * 60)
        self.logger.info("安全配置检查")
        self.logger.info("=" * 60)
        
        if security_status['security_level'] == 'high':
            self.logger.info("✅ 安全等级: 高 - 所有敏感配置都通过环境变量配置")
        elif security_status['security_level'] == 'medium':
            self.logger.warning("⚠️  安全等级: 中 - 部分敏感配置在配置文件中")
            self.logger.warning(f"   建议迁移到环境变量: {security_status['configured_via_file']}")
        else:
            self.logger.error("❌ 安全等级: 低 - 敏感配置在配置文件中明文存储")
            self.logger.error(f"   存在风险的配置: {security_status['configured_via_file']}")
            self.logger.error("   强烈建议使用环境变量存储敏感信息！")
        
        self.logger.info("=" * 60)
    
    def _signal_handler(self, signum, frame):
        self.logger.info(f"接收到信号 {signum}，正在停止监控...")
        self.running = False
    
    def _start_web_server(self):
        """启动Web服务器（在单独线程中运行）"""
        try:
            from src.web.app import WebApp
            from src.utils.database import Database
            
            # 检查是否启用Web界面
            if not self.config.get_bool('ENABLE_WEB', True):
                self.logger.info("Web界面未启用")
                return
            
            # 初始化数据库
            database = Database(self.config)
            
            # 创建Web应用
            web_app = WebApp(self.config, database)
            
            # 获取配置
            host = self.config.get('WEB_HOST', '0.0.0.0')
            port = self.config.get_int('WEB_PORT', 5001)
            debug = self.config.get_bool('WEB_DEBUG', False)
            
            self.logger.info(f"Web界面地址: http://{host}:{port}")
            
            # 运行Web应用（不使用debug模式，避免多线程问题）
            web_app.run(host=host, port=port, debug=False)
            
        except Exception as e:
            self.logger.error(f"Web服务器启动失败: {str(e)}", exc_info=True)
    
    def start(self):
        self.logger.info("=" * 60)
        self.logger.info("局域网安全监控系统启动")
        self.logger.info("=" * 60)
        
        self.running = True
        
        try:
            # 启动Web服务器（在单独线程中）
            if self.config.get_bool('ENABLE_WEB', True):
                self.web_thread = threading.Thread(target=self._start_web_server, daemon=True)
                self.web_thread.start()
                self.logger.info("Web服务器线程已启动")
            
            # 初始化监控系统
            self.monitor.initialize()
            
            # 主监控循环
            while self.running:
                try:
                    self.monitor.run_security_check()
                    
                    interval = int(self.config.get('CHECK_INTERVAL', 300))
                    self.logger.info(f"等待 {interval} 秒后进行下一次检查...")
                    
                    for _ in range(interval):
                        if not self.running:
                            break
                        time.sleep(1)
                        
                except Exception as e:
                    self.logger.error(f"监控循环发生错误: {str(e)}", exc_info=True)
                    time.sleep(60)
                    
        except KeyboardInterrupt:
            self.logger.info("用户中断，正在停止监控...")
        except Exception as e:
            self.logger.error(f"监控程序异常退出: {str(e)}", exc_info=True)
        finally:
            self.stop()
    
    def stop(self):
        self.logger.info("正在停止监控系统...")
        self.monitor.cleanup()
        self.logger.info("监控系统已停止")


def main():
    config_file = os.environ.get('CONFIG_FILE', 'config/config.env')
    
    if not os.path.exists(config_file):
        print(f"错误: 配置文件不存在: {config_file}")
        print("请复制 config/config.env.example 为 config/config.env 并配置")
        sys.exit(1)
    
    monitor = LanSecurityMonitor(config_file)
    monitor.start()


if __name__ == '__main__':
    main()
