#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web管理界面启动脚本
"""

import os
import sys

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.web.app import WebApp
from src.utils.config import Config
from src.utils.database import Database
from src.utils.logger import setup_logger

logger = setup_logger('LanSecurityMonitor.WebRunner')


def main():
    """启动Web管理界面"""
    try:
        logger.info("=" * 60)
        logger.info("启动Web管理界面")
        logger.info("=" * 60)
        
        # 加载配置
        config = Config()
        
        # 检查是否启用Web界面
        if not config.get_bool('ENABLE_WEB', True):
            logger.error("Web界面未启用，请在配置文件中设置 ENABLE_WEB=true")
            return
        
        # 初始化数据库
        database = Database(config)
        
        # 创建Web应用
        web_app = WebApp(config, database)
        
        # 获取配置
        host = config.get('WEB_HOST', '0.0.0.0')
        port = config.get_int('WEB_PORT', 5000)
        debug = config.get_bool('WEB_DEBUG', False)
        
        logger.info(f"Web界面地址: http://{host}:{port}")
        logger.info(f"调试模式: {'开启' if debug else '关闭'}")
        logger.info("=" * 60)
        
        # 运行Web应用
        web_app.run(host=host, port=port, debug=debug)
        
    except KeyboardInterrupt:
        logger.info("收到中断信号，正在关闭...")
    except Exception as e:
        logger.error(f"启动Web界面失败: {str(e)}", exc_info=True)


if __name__ == '__main__':
    main()
