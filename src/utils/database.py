#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据库工具模块
"""

import os
import json
import sqlite3
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional


class Database:
    """数据库管理类"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        self.db_type = config.get('DB_TYPE', 'sqlite')
        self.db_file = config.get('DB_FILE', 'data/security.db')
        
        self.conn = None
        self._initialize()
    
    def _initialize(self):
        """初始化数据库"""
        if self.db_type == 'sqlite':
            if not os.path.isabs(self.db_file):
                self.db_file = os.path.abspath(self.db_file)
            
            db_dir = os.path.dirname(self.db_file)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
            
            self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
            self._create_tables()
            
            self.logger.info(f"数据库文件路径: {self.db_file}")
    
    def _create_tables(self):
        """创建数据表"""
        cursor = self.conn.cursor()
        
        # 系统状态表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_status (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT
            )
        ''')
        
        # 设备表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ip TEXT,
                hostname TEXT,
                vendor TEXT,
                os_type TEXT,
                device_type TEXT,
                category TEXT,
                risk_level TEXT,
                first_seen TEXT,
                last_seen TEXT,
                is_known INTEGER DEFAULT 0,
                notes TEXT
            )
        ''')
        
        # 威胁记录表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                device_mac TEXT,
                device_ip TEXT,
                threat_type TEXT,
                severity TEXT,
                description TEXT,
                action_taken TEXT
            )
        ''')
        
        # 检查记录表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS check_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                total_devices INTEGER,
                new_devices INTEGER,
                offline_devices INTEGER,
                threats INTEGER,
                check_duration REAL
            )
        ''')
        
        # 设备行为记录表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS device_behaviors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT,
                ip TEXT,
                hostname TEXT,
                timestamp TEXT,
                hour INTEGER,
                day_of_week INTEGER,
                status TEXT
            )
        ''')
        
        self.conn.commit()
    
    def load_known_devices(self) -> Dict:
        """加载已知设备"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM devices WHERE is_known = 1')
        
        devices = {}
        for row in cursor.fetchall():
            mac = row[0]
            devices[mac] = {
                'mac': mac,
                'ip': row[1],
                'hostname': row[2],
                'vendor': row[3],
                'os_type': row[4],
                'device_type': row[5],
                'category': row[6],
                'risk_level': row[7],
                'first_seen': row[8],
                'last_seen': row[9],
                'is_known': bool(row[10]),
                'notes': row[11]
            }
        
        return devices
    
    def save_device(self, device: Dict):
        """保存设备信息"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO devices 
            (mac, ip, hostname, vendor, os_type, device_type, category, risk_level, first_seen, last_seen, is_known, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            device.get('mac'),
            device.get('ip'),
            device.get('hostname'),
            device.get('vendor'),
            device.get('os_type'),
            device.get('device_type'),
            device.get('category'),
            device.get('risk_level'),
            device.get('first_seen', datetime.now().isoformat()),
            datetime.now().isoformat(),
            device.get('is_known', 0),
            device.get('notes', '')
        ))
        self.conn.commit()
    
    def save_threat(self, threat: Dict):
        """保存威胁记录"""
        cursor = self.conn.cursor()
        device = threat.get('device', {})
        cursor.execute('''
            INSERT INTO threats 
            (timestamp, device_mac, device_ip, threat_type, severity, description, action_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            device.get('mac'),
            device.get('ip'),
            threat.get('type'),
            threat.get('severity'),
            threat.get('description'),
            threat.get('action_taken', '')
        ))
        self.conn.commit()
    
    def save_check_result(self, result: Dict):
        """保存检查结果"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO check_results 
            (timestamp, total_devices, new_devices, offline_devices, threats, check_duration)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            result.get('timestamp'),
            result.get('total_devices'),
            result.get('new_devices'),
            result.get('offline_devices'),
            result.get('threats'),
            result.get('check_duration')
        ))
        self.conn.commit()
    
    def update_devices(self, devices: Dict):
        """批量更新设备"""
        for mac, device in devices.items():
            self.save_device(device)
    
    def save_device_behavior(self, behavior: Dict):
        """保存设备行为"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO device_behaviors 
            (mac, ip, hostname, timestamp, hour, day_of_week, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            behavior.get('mac'),
            behavior.get('ip'),
            behavior.get('hostname'),
            behavior.get('timestamp'),
            behavior.get('hour'),
            behavior.get('day_of_week'),
            behavior.get('status')
        ))
        self.conn.commit()
    
    def get_device_behaviors(self, mac: str, days: int = 30) -> List[Dict]:
        """获取设备行为记录
        
        Args:
            mac: 设备MAC地址
            days: 天数
            
        Returns:
            行为记录列表
        """
        cursor = self.conn.cursor()
        
        # 计算时间范围
        import datetime
        start_time = (datetime.datetime.now() - datetime.timedelta(days=days)).isoformat()
        
        cursor.execute('''
            SELECT * FROM device_behaviors 
            WHERE mac = ? AND timestamp >= ? 
            ORDER BY timestamp DESC
        ''', (mac, start_time))
        
        behaviors = []
        for row in cursor.fetchall():
            behaviors.append({
                'id': row[0],
                'mac': row[1],
                'ip': row[2],
                'hostname': row[3],
                'timestamp': row[4],
                'hour': row[5],
                'day_of_week': row[6],
                'status': row[7]
            })
        
        return behaviors
    
    def cleanup_old_behavior_records(self, days: int = 30):
        """清理旧的行为记录
        
        Args:
            days: 保留天数
        """
        cursor = self.conn.cursor()
        
        # 计算时间范围
        import datetime
        cutoff_time = (datetime.datetime.now() - datetime.timedelta(days=days)).isoformat()
        
        cursor.execute('DELETE FROM device_behaviors WHERE timestamp < ?', (cutoff_time,))
        deleted_count = cursor.rowcount
        
        self.conn.commit()
        
        if deleted_count > 0:
            logger = logging.getLogger('LanSecurityMonitor')
            logger.info(f"清理了 {deleted_count} 条旧的行为记录")
    
    def close(self):
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()
    
    def get_system_status(self, key: str, default: str = None) -> Optional[str]:
        """获取系统状态
        
        Args:
            key: 状态键
            default: 默认值
            
        Returns:
            状态值
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT value FROM system_status WHERE key = ?', (key,))
        result = cursor.fetchone()
        return result[0] if result else default
    
    def set_system_status(self, key: str, value: str):
        """设置系统状态
        
        Args:
            key: 状态键
            value: 状态值
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO system_status (key, value, updated_at)
            VALUES (?, ?, ?)
        ''', (key, value, datetime.now().isoformat()))
        self.conn.commit()
    
    def is_first_run(self) -> bool:
        """检查是否为首次运行
        
        Returns:
            是否为首次运行
        """
        # 检查系统状态
        first_run = self.get_system_status('first_run', 'true')
        
        # 如果系统状态标记为 false，检查设备数量和行为数据
        if first_run == 'false':
            # 如果设备数量 < 5，仍然认为是首次运行
            device_count = self.get_total_devices_count()
            if device_count < 5:
                self.logger.info(f"设备数量为 {device_count}，仍然认为是首次运行")
                return True
            
            # 检查是否有足够的行为观察数据
            # 统计有足够观察次数的设备数量（每个设备至少7次观察）
            devices_with_sufficient_data = self.get_devices_with_sufficient_behavior_data(min_observations=7)
            
            # 如果有足够观察数据的设备数量 < 设备总数的50%，仍然认为是首次运行
            if devices_with_sufficient_data < device_count * 0.5:
                self.logger.info(f"有足够观察数据的设备数量为 {devices_with_sufficient_data}/{device_count}，仍然认为是首次运行")
                return True
            
            # 检查行为观察数据的时间范围
            # 如果最早的行为观察数据是在最近24小时内，仍然认为是首次运行
            earliest_behavior_time = self.get_earliest_behavior_time()
            if earliest_behavior_time:
                from datetime import datetime, timedelta
                time_diff = datetime.now() - earliest_behavior_time
                if time_diff < timedelta(hours=24):
                    self.logger.info(f"行为观察数据时间范围不足24小时（{time_diff}），仍然认为是首次运行")
                    return True
            
            return False
        
        return first_run == 'true'
    
    def mark_first_run_completed(self):
        """标记首次运行已完成"""
        self.set_system_status('first_run', 'false')
        self.logger.info("首次运行标记已完成")
    
    def mark_all_devices_as_known(self):
        """将所有设备标记为已知设备
        
        用于学习期结束后，将学习期间记录的所有设备标记为已知
        """
        cursor = self.conn.cursor()
        cursor.execute('UPDATE devices SET is_known = 1 WHERE is_known = 0')
        updated_count = cursor.rowcount
        self.conn.commit()
        
        if updated_count > 0:
            self.logger.info(f"已将 {updated_count} 个设备标记为已知设备")
        
        return updated_count
    
    def get_total_devices_count(self) -> int:
        """获取设备总数
        
        Returns:
            设备总数
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM devices')
        result = cursor.fetchone()
        return result[0] if result else 0
    
    def get_total_behavior_count(self) -> int:
        """获取行为观察总次数
        
        Returns:
            行为观察总次数
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM device_behaviors')
            result = cursor.fetchone()
            return result[0] if result else 0
        except Exception as e:
            self.logger.error(f"获取行为观察次数失败: {str(e)}")
            return 0
    
    def get_last_check_time(self) -> str:
        """获取最后扫描时间
        
        Returns:
            最后扫描时间字符串，如果没有记录则返回None
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT MAX(timestamp) FROM check_results')
            result = cursor.fetchone()
            return result[0] if result and result[0] else None
        except Exception as e:
            self.logger.error(f"获取最后扫描时间失败: {str(e)}")
            return None
    
    def get_devices_with_sufficient_behavior_data(self, min_observations: int = 7) -> int:
        """获取有足够行为观察数据的设备数量
        
        Args:
            min_observations: 最小观察次数
            
        Returns:
            有足够观察数据的设备数量
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT COUNT(DISTINCT mac) 
                FROM device_behaviors 
                GROUP BY mac 
                HAVING COUNT(*) >= ?
            ''', (min_observations,))
            results = cursor.fetchall()
            return len(results)
        except Exception as e:
            self.logger.error(f"获取有足够观察数据的设备数量失败: {str(e)}")
            return 0
    
    def get_earliest_behavior_time(self):
        """获取最早的行为观察时间
        
        Returns:
            最早的行为观察时间（datetime对象），如果没有数据则返回None
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT MIN(timestamp) FROM device_behaviors')
            result = cursor.fetchone()
            if result and result[0]:
                from datetime import datetime
                return datetime.fromisoformat(result[0])
            return None
        except Exception as e:
            self.logger.error(f"获取最早行为观察时间失败: {str(e)}")
            return None
    
    def reset_first_run(self):
        """重置首次运行状态（用于测试或重新初始化）"""
        self.set_system_status('first_run', 'true')
        self.logger.warning("首次运行状态已重置")
    
    def get_first_run_status(self) -> Dict[str, Any]:
        """获取首次运行状态信息
        
        Returns:
            首次运行状态字典
        """
        first_run = self.get_system_status('first_run', 'true')
        device_count = self.get_total_devices_count()
        devices_with_sufficient_data = self.get_devices_with_sufficient_behavior_data(min_observations=7)
        
        # 计算行为观察时间范围
        earliest_time = self.get_earliest_behavior_time()
        behavior_time_hours = 0
        if earliest_time:
            time_diff = datetime.now() - earliest_time
            behavior_time_hours = time_diff.total_seconds() / 3600
        
        return {
            'is_first_run': first_run == 'true',
            'device_count': device_count,
            'devices_with_sufficient_data': devices_with_sufficient_data,
            'target_devices': int(device_count * 0.5),
            'behavior_time_hours': behavior_time_hours,
            'threshold': 10,
            'progress': min(device_count / 10 * 100, 100)
        }
    
    def get_threats(self, limit: int = 20, offset: int = 0, severity: str = None) -> List[Dict]:
        """获取威胁记录
        
        Args:
            limit: 返回数量限制
            offset: 偏移量
            severity: 严重程度过滤
            
        Returns:
            威胁记录列表
        """
        try:
            cursor = self.conn.cursor()
            
            if severity:
                cursor.execute('''
                    SELECT * FROM threats 
                    WHERE severity = ?
                    ORDER BY timestamp DESC 
                    LIMIT ? OFFSET ?
                ''', (severity, limit, offset))
            else:
                cursor.execute('''
                    SELECT * FROM threats 
                    ORDER BY timestamp DESC 
                    LIMIT ? OFFSET ?
                ''', (limit, offset))
            
            results = cursor.fetchall()
            
            threats = []
            for row in results:
                threats.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'device_mac': row[2],
                    'device_ip': row[3],
                    'type': row[4],
                    'severity': row[5],
                    'description': row[6],
                    'details': row[7] if len(row) > 7 else None
                })
            
            return threats
        except Exception as e:
            self.logger.error(f"获取威胁记录失败: {str(e)}")
            return []
    
    def get_threats_count(self, severity: str = None) -> int:
        """获取威胁总数
        
        Args:
            severity: 严重程度过滤
            
        Returns:
            威胁总数
        """
        try:
            cursor = self.conn.cursor()
            
            if severity:
                cursor.execute('SELECT COUNT(*) FROM threats WHERE severity = ?', (severity,))
            else:
                cursor.execute('SELECT COUNT(*) FROM threats')
            
            result = cursor.fetchone()
            return result[0] if result else 0
        except Exception as e:
            self.logger.error(f"获取威胁总数失败: {str(e)}")
            return 0
    
    def get_threat_by_id(self, threat_id: int) -> Optional[Dict]:
        """获取威胁详情
        
        Args:
            threat_id: 威胁ID
            
        Returns:
            威胁详情字典
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT * FROM threats WHERE id = ?', (threat_id,))
            row = cursor.fetchone()
            
            if row:
                return {
                    'id': row[0],
                    'timestamp': row[1],
                    'device_mac': row[2],
                    'device_ip': row[3],
                    'type': row[4],
                    'severity': row[5],
                    'description': row[6],
                    'details': row[7] if len(row) > 7 else None
                }
            return None
        except Exception as e:
            self.logger.error(f"获取威胁详情失败: {str(e)}")
            return None
    
    def delete_threat(self, threat_id: int) -> bool:
        """删除威胁记录
        
        Args:
            threat_id: 威胁ID
            
        Returns:
            是否删除成功
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('DELETE FROM threats WHERE id = ?', (threat_id,))
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            self.logger.error(f"删除威胁记录失败: {str(e)}")
            return False
    
    def delete_all_threats(self) -> bool:
        """删除所有威胁记录
        
        Returns:
            是否删除成功
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('DELETE FROM threats')
            self.conn.commit()
            return True
        except Exception as e:
            self.logger.error(f"删除所有威胁记录失败: {str(e)}")
            return False
    
    def get_threat_stats(self, days: int = 7) -> Dict[str, Any]:
        """获取威胁统计
        
        Args:
            days: 统计天数
            
        Returns:
            威胁统计字典
        """
        try:
            cursor = self.conn.cursor()
            
            # 获取总数
            total = self.get_threats_count()
            
            # 获取最近N天的威胁数量
            cursor.execute('''
                SELECT COUNT(*) FROM threats 
                WHERE timestamp >= datetime('now', '-' || ? || ' days')
            ''', (days,))
            recent_count = cursor.fetchone()[0]
            
            # 按严重程度统计
            cursor.execute('''
                SELECT severity, COUNT(*) as count 
                FROM threats 
                WHERE timestamp >= datetime('now', '-' || ? || ' days')
                GROUP BY severity
            ''', (days,))
            severity_stats = {row[0]: row[1] for row in cursor.fetchall()}
            
            # 按类型统计
            cursor.execute('''
                SELECT type, COUNT(*) as count 
                FROM threats 
                WHERE timestamp >= datetime('now', '-' || ? || ' days')
                GROUP BY type
            ''', (days,))
            type_stats = {row[0]: row[1] for row in cursor.fetchall()}
            
            return {
                'total': total,
                'recent_count': recent_count,
                'by_severity': severity_stats,
                'by_type': type_stats
            }
        except Exception as e:
            self.logger.error(f"获取威胁统计失败: {str(e)}")
            return {
                'total': 0,
                'recent_count': 0,
                'by_severity': {},
                'by_type': {}
            }
