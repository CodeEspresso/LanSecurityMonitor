#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
重置首次运行状态
"""

import os
import sys
import sqlite3

def reset_first_run():
    """重置首次运行状态"""
    db_file = 'data/security.db'
    
    if not os.path.exists(db_file):
        print(f"❌ 数据库文件不存在: {db_file}")
        return False
    
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # 检查 system_status 表是否存在
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='system_status'")
        if not cursor.fetchone():
            print("⚠️  system_status 表不存在，创建中...")
            cursor.execute('''
                CREATE TABLE system_status (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT
                )
            ''')
        
        # 重置首次运行状态
        from datetime import datetime
        cursor.execute('''
            INSERT OR REPLACE INTO system_status (key, value, updated_at)
            VALUES (?, ?, ?)
        ''', ('first_run', 'true', datetime.now().isoformat()))
        
        conn.commit()
        
        # 获取设备数量
        cursor.execute('SELECT COUNT(*) FROM devices')
        device_count = cursor.fetchone()[0]
        
        conn.close()
        
        print("✅ 首次运行状态已重置")
        print(f"📊 当前设备数量: {device_count}")
        print(f"📋 首次运行阈值: 10")
        print(f"📈 进度: {min(device_count / 10 * 100, 100):.1f}%")
        
        return True
        
    except Exception as e:
        print(f"❌ 重置失败: {str(e)}")
        return False

if __name__ == '__main__':
    print("=" * 60)
    print("重置首次运行状态")
    print("=" * 60)
    
    if reset_first_run():
        print("\n✅ 重置成功！")
        print("\n下一步:")
        print("1. 重启系统: docker-compose restart")
        print("2. 查看日志: docker-compose logs -f")
        print("\n系统将进入首次运行模式，新设备通知将被关闭。")
    else:
        print("\n❌ 重置失败！")
        sys.exit(1)
