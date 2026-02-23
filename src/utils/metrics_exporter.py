#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
指标导出模块
"""

import logging
import json
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from typing import Dict, List, Optional

logger = logging.getLogger('LanSecurityMonitor')


class MetricsExporter:
    """指标导出器"""
    
    def __init__(self, config, database):
        self.config = config
        self.database = database
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        # 配置项
        self.enable_metrics = config.get_bool('ENABLE_METRICS', True)
        self.metrics_port = config.get_int('METRICS_PORT', 9100)
        self.metrics_host = config.get('METRICS_HOST', '0.0.0.0')
        
        self.server = None
        self.server_thread = None
    
    def initialize(self):
        """初始化指标导出器"""
        if self.enable_metrics:
            self.logger.info("初始化指标导出器")
            self.logger.info(f"监听地址: {self.metrics_host}:{self.metrics_port}")
            self._start_server()
    
    def _start_server(self):
        """启动HTTP服务器"""
        try:
            handler = MetricsHandler
            handler.database = self.database
            
            self.server = HTTPServer((self.metrics_host, self.metrics_port), handler)
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()
            
            self.logger.info(f"指标服务器已启动: http://{self.metrics_host}:{self.metrics_port}")
            self.logger.info(f"Prometheus指标: http://{self.metrics_host}:{self.metrics_port}/metrics")
            self.logger.info(f"设备API: http://{self.metrics_host}:{self.metrics_port}/api/devices")
            self.logger.info(f"威胁API: http://{self.metrics_host}:{self.metrics_port}/api/threats")
            self.logger.info(f"统计API: http://{self.metrics_host}:{self.metrics_port}/api/stats")
            
        except Exception as e:
            self.logger.error(f"启动指标服务器失败: {str(e)}")
    
    def cleanup(self):
        """清理资源"""
        if self.server:
            self.logger.info("停止指标服务器")
            self.server.shutdown()
            if self.server_thread:
                self.server_thread.join(timeout=5)


class MetricsHandler(BaseHTTPRequestHandler):
    """HTTP请求处理器"""
    
    database = None
    
    def do_GET(self):
        """处理GET请求"""
        if self.path == '/metrics':
            self._handle_metrics()
        elif self.path == '/api/devices':
            self._handle_api_devices()
        elif self.path == '/api/threats':
            self._handle_api_threats()
        elif self.path == '/api/stats':
            self._handle_api_stats()
        else:
            self._handle_not_found()
    
    def _handle_metrics(self):
        """处理Prometheus指标请求"""
        try:
            metrics = self._generate_prometheus_metrics()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(metrics.encode('utf-8'))
        except Exception as e:
            self._send_error(500, f"Internal Server Error: {str(e)}")
    
    def _handle_api_devices(self):
        """处理设备API请求"""
        try:
            devices = self._get_devices_data()
            self._send_json(devices)
        except Exception as e:
            self._send_error(500, f"Internal Server Error: {str(e)}")
    
    def _handle_api_threats(self):
        """处理威胁API请求"""
        try:
            threats = self._get_threats_data()
            self._send_json(threats)
        except Exception as e:
            self._send_error(500, f"Internal Server Error: {str(e)}")
    
    def _handle_api_stats(self):
        """处理统计API请求"""
        try:
            stats = self._get_stats_data()
            self._send_json(stats)
        except Exception as e:
            self._send_error(500, f"Internal Server Error: {str(e)}")
    
    def _handle_not_found(self):
        """处理404请求"""
        self._send_error(404, "Not Found")
    
    def _generate_prometheus_metrics(self) -> str:
        """生成Prometheus格式的指标"""
        metrics = []
        
        # 添加指标注释
        metrics.append('# HELP lan_security_devices_total 设备总数')
        metrics.append('# TYPE lan_security_devices_total gauge')
        metrics.append('# HELP lan_security_threats_total 威胁总数')
        metrics.append('# TYPE lan_security_threats_total gauge')
        metrics.append('# HELP lan_security_new_devices_total 新设备总数')
        metrics.append('# TYPE lan_security_new_devices_total counter')
        metrics.append('# HELP lan_security_check_duration_seconds 检查持续时间')
        metrics.append('# TYPE lan_security_check_duration_seconds gauge')
        
        # 获取统计数据
        stats = self._get_stats_data()
        
        # 添加指标值
        metrics.append(f'lan_security_devices_total {stats.get("total_devices", 0)}')
        metrics.append(f'lan_security_threats_total {stats.get("total_threats", 0)}')
        metrics.append(f'lan_security_new_devices_total {stats.get("total_new_devices", 0)}')
        if stats.get('last_check_duration'):
            metrics.append(f'lan_security_check_duration_seconds {stats.get("last_check_duration", 0)}')
        
        # 添加设备类型指标
        device_types = stats.get('device_types', {})
        for device_type, count in device_types.items():
            metrics.append(f'lan_security_devices_by_type{{type="{device_type}"}} {count}')
        
        # 添加时间戳
        metrics.append(f'lan_security_last_update {int(datetime.now().timestamp())}')
        
        return '\n'.join(metrics)
    
    def _get_devices_data(self) -> List[Dict]:
        """获取设备数据"""
        if not self.database:
            return []
        
        try:
            cursor = self.database.conn.cursor()
            cursor.execute('SELECT * FROM devices ORDER BY last_seen DESC')
            
            devices = []
            for row in cursor.fetchall():
                devices.append({
                    'mac': row[0],
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
                })
            
            return devices
        except Exception as e:
            logger.error(f"获取设备数据失败: {str(e)}")
            return []
    
    def _get_threats_data(self) -> List[Dict]:
        """获取威胁数据"""
        if not self.database:
            return []
        
        try:
            cursor = self.database.conn.cursor()
            cursor.execute('SELECT * FROM threats ORDER BY timestamp DESC LIMIT 100')
            
            threats = []
            for row in cursor.fetchall():
                threats.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'device_mac': row[2],
                    'device_ip': row[3],
                    'threat_type': row[4],
                    'severity': row[5],
                    'description': row[6],
                    'action_taken': row[7]
                })
            
            return threats
        except Exception as e:
            logger.error(f"获取威胁数据失败: {str(e)}")
            return []
    
    def _get_stats_data(self) -> Dict:
        """获取统计数据"""
        if not self.database:
            return {}
        
        try:
            stats = {}
            
            # 获取设备统计
            cursor = self.database.conn.cursor()
            
            # 设备总数
            cursor.execute('SELECT COUNT(*) FROM devices')
            stats['total_devices'] = cursor.fetchone()[0]
            
            # 已知设备数
            cursor.execute('SELECT COUNT(*) FROM devices WHERE is_known = 1')
            stats['known_devices'] = cursor.fetchone()[0]
            
            # 威胁总数
            cursor.execute('SELECT COUNT(*) FROM threats')
            stats['total_threats'] = cursor.fetchone()[0]
            
            # 新设备总数
            cursor.execute('SELECT COUNT(*) FROM devices WHERE is_known = 0')
            stats['total_new_devices'] = cursor.fetchone()[0]
            
            # 最近检查结果
            cursor.execute('SELECT * FROM check_results ORDER BY timestamp DESC LIMIT 1')
            last_check = cursor.fetchone()
            if last_check:
                stats['last_check'] = last_check[1]
                stats['last_check_duration'] = last_check[6]
                stats['last_check_devices'] = last_check[2]
                stats['last_check_new_devices'] = last_check[3]
                stats['last_check_threats'] = last_check[5]
            
            # 设备类型统计
            cursor.execute('SELECT device_type, COUNT(*) FROM devices GROUP BY device_type')
            device_types = {}
            for row in cursor.fetchall():
                device_type = row[0] or 'unknown'
                device_types[device_type] = row[1]
            stats['device_types'] = device_types
            
            # 设备分类统计
            cursor.execute('SELECT category, COUNT(*) FROM devices GROUP BY category')
            categories = {}
            for row in cursor.fetchall():
                category = row[0] or 'unknown'
                categories[category] = row[1]
            stats['categories'] = categories
            
            # 威胁类型统计
            cursor.execute('SELECT threat_type, COUNT(*) FROM threats GROUP BY threat_type')
            threat_types = {}
            for row in cursor.fetchall():
                threat_type = row[0] or 'unknown'
                threat_types[threat_type] = row[1]
            stats['threat_types'] = threat_types
            
            # 时间戳
            stats['timestamp'] = datetime.now().isoformat()
            
            return stats
            
        except Exception as e:
            logger.error(f"获取统计数据失败: {str(e)}")
            return {}
    
    def _send_json(self, data):
        """发送JSON响应"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')  # 允许跨域
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8'))
    
    def _send_error(self, code, message):
        """发送错误响应"""
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(message.encode('utf-8'))
    
    def _handle_not_found(self):
        """处理404"""
        self._send_error(404, "Not Found")
    
    def log_message(self, format, *args):
        """重写日志方法"""
        # 禁用默认日志
        pass