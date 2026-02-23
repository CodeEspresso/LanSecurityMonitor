#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
重置学习期脚本
用于重新开始学习期（清除行为观察数据，但保留设备数据）
"""

import os
import sys
import sqlite3
from datetime import datetime

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.utils.logger import setup_logger

logger = setup_logger()


def reset_learning_period():
    """重置学习期"""
    db_file = 'data/security.db'
    
    if not os.path.exists(db_file):
        logger.error("数据库文件不存在")
        return False
    
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        logger.info("=" * 60)
        logger.info("🔄 重置学习期")
        logger.info("=" * 60)
        
        # 显示当前状态
        cursor.execute('SELECT COUNT(*) FROM devices')
        device_count = cursor.fetchone()[0]
        logger.info(f"当前设备数量: {device_count}")
        
        cursor.execute('SELECT COUNT(*) FROM device_behaviors')
        behavior_count = cursor.fetchone()[0]
        logger.info(f"当前行为观察次数: {behavior_count}")
        
        cursor.execute('SELECT value FROM system_status WHERE key="first_run"')
        result = cursor.fetchone()
        first_run_status = result[0] if result else 'true'
        logger.info(f"当前学习期状态: {'学习中' if first_run_status == 'true' else '已完成'}")
        
        # 询问用户确认
        print("\n" + "=" * 60)
        print("⚠️  警告：重置学习期将会：")
        print("  1. 清除所有行为观察数据")
        print("  2. 重新进入学习期")
        print("  3. 学习期期间只通知严重威胁（high/critical级别）")
        print("  4. 保留设备数据")
        print("=" * 60)
        
        confirm = input("\n确认重置学习期？(yes/no): ").strip().lower()
        
        if confirm != 'yes':
            logger.info("取消重置")
            conn.close()
            return False
        
        # 清除行为观察数据
        logger.info("清除行为观察数据...")
        cursor.execute('DELETE FROM device_behaviors')
        
        # 重置学习期状态
        logger.info("重置学习期状态...")
        cursor.execute('UPDATE system_status SET value="true" WHERE key="first_run"')
        
        # 提交更改
        conn.commit()
        
        # 显示重置后的状态
        cursor.execute('SELECT COUNT(*) FROM device_behaviors')
        behavior_count = cursor.fetchone()[0]
        logger.info(f"重置后行为观察次数: {behavior_count}")
        
        logger.info("=" * 60)
        logger.info("✅ 学习期重置完成")
        logger.info("=" * 60)
        logger.info("系统将在下次运行时重新进入学习期")
        logger.info("学习期要求：")
        logger.info("  • 行为观察数据时间范围 >= 24小时")
        logger.info("  • 有足够观察数据的设备 >= 设备总数的50%")
        logger.info("=" * 60)
        
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"重置学习期失败: {str(e)}")
        return False


def show_learning_status():
    """显示学习期状态"""
    db_file = 'data/security.db'
    
    if not os.path.exists(db_file):
        logger.error("数据库文件不存在")
        return
    
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        logger.info("=" * 60)
        logger.info("📊 学习期状态")
        logger.info("=" * 60)
        
        # 设备数量
        cursor.execute('SELECT COUNT(*) FROM devices')
        device_count = cursor.fetchone()[0]
        logger.info(f"设备数量: {device_count}")
        
        # 行为观察次数
        cursor.execute('SELECT COUNT(*) FROM device_behaviors')
        behavior_count = cursor.fetchone()[0]
        logger.info(f"行为观察总次数: {behavior_count}")
        
        # 有足够观察数据的设备数量
        cursor.execute('''
            SELECT COUNT(DISTINCT mac) 
            FROM device_behaviors 
            GROUP BY mac 
            HAVING COUNT(*) >= 7
        ''')
        devices_with_sufficient_data = len(cursor.fetchall())
        logger.info(f"有足够观察数据的设备: {devices_with_sufficient_data}/{device_count}")
        
        # 最早的行为观察时间
        cursor.execute('SELECT MIN(timestamp) FROM device_behaviors')
        result = cursor.fetchone()
        if result and result[0]:
            earliest_time = datetime.fromisoformat(result[0])
            time_diff = datetime.now() - earliest_time
            logger.info(f"行为观察数据时间范围: {time_diff}")
        else:
            logger.info("行为观察数据时间范围: 无数据")
        
        # 学习期状态
        cursor.execute('SELECT value FROM system_status WHERE key="first_run"')
        result = cursor.fetchone()
        first_run_status = result[0] if result else 'true'
        
        logger.info("=" * 60)
        if first_run_status == 'true':
            logger.info("⚠️  当前状态: 学习期")
            logger.info("学习期策略：")
            logger.info("  ✅ 严重威胁通知: 开启（high/critical级别）")
            logger.info("  ⏸️  中等威胁通知: 关闭")
            logger.info("  ⏸️  新设备通知: 关闭")
            logger.info("  ⏸️  行为分析: 关闭")
        else:
            logger.info("✅ 当前状态: 正常运行模式")
            logger.info("正常运行策略：")
            logger.info("  ✅ 所有威胁通知: 开启")
            logger.info("  ✅ 新设备通知: 开启")
            logger.info("  ✅ 行为分析: 开启")
        logger.info("=" * 60)
        
        conn.close()
        
    except Exception as e:
        logger.error(f"获取学习期状态失败: {str(e)}")


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='学习期管理工具')
    parser.add_argument('--status', action='store_true', help='显示学习期状态')
    parser.add_argument('--reset', action='store_true', help='重置学习期')
    
    args = parser.parse_args()
    
    if args.status:
        show_learning_status()
    elif args.reset:
        reset_learning_period()
    else:
        show_learning_status()
        print("\n使用方法：")
        print("  python3 reset_learning_period.py --status  # 显示学习期状态")
        print("  python3 reset_learning_period.py --reset   # 重置学习期")
