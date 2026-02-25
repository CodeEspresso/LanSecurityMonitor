#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web管理界面 - Flask应用
"""

from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
import logging
import os
import sys
from datetime import datetime, timedelta

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.config import Config
from src.utils.database import Database
from src.utils.logger import setup_logger

logger = setup_logger('LanSecurityMonitor.Web')


class WebApp:
    """Web应用类"""
    
    def __init__(self, config, database):
        self.config = config
        self.database = database
        
        # 获取项目根目录
        import os
        root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        template_dir = os.path.join(root_dir, 'web', 'templates')
        static_dir = os.path.join(root_dir, 'web', 'static')
        
        self.app = Flask(__name__, 
                        template_folder=template_dir,
                        static_folder=static_dir)
        
        # 配置
        self.app.config['SECRET_KEY'] = config.get('WEB_SECRET_KEY', 'lan-security-monitor-secret-key-2024')
        self.app.config['JSON_AS_ASCII'] = False  # 支持中文
        
        # 启用CORS
        CORS(self.app)
        
        # 用户认证
        self.login_manager = LoginManager()
        self.login_manager.init_app(self.app)
        self.login_manager.login_view = 'login'
        
        # 用户类 - 定义为实例属性以便在路由中访问
        class _User(UserMixin):
            def __init__(self, id, username):
                self.id = id
                self.username = username
        self.User = _User
        
        @self.login_manager.user_loader
        def load_user(user_id):
            if user_id == '1':
                web_username = self.database.get_system_status('WEB_USERNAME', 
                    self.config.get('WEB_USERNAME', 'admin'))
                return self.User(1, web_username)
            return None
        
        # 注册路由
        self._register_routes()
        
        logger.info("Web应用初始化完成")
    
    def _register_routes(self):
        """注册路由"""
        
        # ==================== 静态文件 ====================
        
        @self.app.route('/')
        @login_required
        def index():
            """主页"""
            return render_template('index.html')
        
        @self.app.route('/login')
        def login():
            """登录页面"""
            return render_template('login.html')
        
        @self.app.route('/devices')
        @login_required
        def devices():
            """设备管理页面"""
            return render_template('devices.html')
        
        @self.app.route('/threats')
        @login_required
        def threats():
            """威胁记录页面"""
            return render_template('threats.html')
        
        @self.app.route('/settings')
        @login_required
        def settings():
            """系统设置页面"""
            return render_template('settings.html')
        
        # ==================== 认证API ====================
        
        @self.app.route('/api/login', methods=['POST'])
        def api_login():
            """登录API"""
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            
            web_username = self.database.get_system_status('WEB_USERNAME', 
                self.config.get('WEB_USERNAME', 'admin'))
            web_password = self.database.get_system_status('WEB_PASSWORD', 
                self.config.get('WEB_PASSWORD', 'admin123'))
            
            if username == web_username and password == web_password:
                from flask_login import login_user
                user = self.User(1, username)
                login_user(user)
                return jsonify({'success': True, 'message': '登录成功'})
            else:
                return jsonify({'success': False, 'message': '用户名或密码错误'}), 401
        
        @self.app.route('/api/logout', methods=['POST'])
        @login_required
        def api_logout():
            """登出API"""
            from flask_login import logout_user
            logout_user()
            return jsonify({'success': True, 'message': '登出成功'})
        
        @self.app.route('/api/user/info')
        @login_required
        def api_user_info():
            """获取当前用户信息"""
            return jsonify({
                'username': current_user.username if hasattr(current_user, 'username') else 'admin'
            })
        
        # ==================== 设备管理API ====================
        
        @self.app.route('/api/devices')
        @login_required
        def api_get_devices():
            """获取设备列表"""
            try:
                devices = self.database.load_known_devices()
                device_list = []
                
                offline_threshold = self.config.get_int('DEVICE_OFFLINE_THRESHOLD', 600)
                
                for mac, device in devices.items():
                    is_online = self._is_device_online(device.get('last_seen'), offline_threshold)
                    
                    device_list.append({
                        'mac': mac,
                        'ip': device.get('ip'),
                        'hostname': device.get('hostname', 'Unknown'),
                        'device_type': device.get('device_type', 'unknown'),
                        'vendor': device.get('vendor', 'Unknown'),
                        'first_seen': device.get('first_seen'),
                        'last_seen': device.get('last_seen'),
                        'is_online': is_online,
                        'category': device.get('category', 'unknown'),
                        'notes': device.get('notes', '')
                    })
                
                # 按IP排序
                device_list.sort(key=lambda x: tuple(map(int, x['ip'].split('.'))))
                
                return jsonify({
                    'success': True,
                    'devices': device_list,
                    'total': len(device_list)
                })
            except Exception as e:
                logger.error(f"获取设备列表失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/devices/<mac>')
        @login_required
        def api_get_device(mac):
            """获取设备详情"""
            try:
                devices = self.database.load_known_devices()
                device = devices.get(mac)
                
                if not device:
                    return jsonify({'success': False, 'message': '设备不存在'}), 404
                
                # 获取设备行为历史
                behaviors = self.database.get_device_behaviors(mac, days=7)
                
                return jsonify({
                    'success': True,
                    'device': device,
                    'behaviors': behaviors
                })
            except Exception as e:
                logger.error(f"获取设备详情失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/devices/stats')
        @login_required
        def api_get_device_stats():
            """获取设备统计"""
            try:
                devices = self.database.load_known_devices()
                
                offline_threshold = self.config.get_int('DEVICE_OFFLINE_THRESHOLD', 600)
                
                total = len(devices)
                online = sum(1 for d in devices.values() 
                            if self._is_device_online(d.get('last_seen'), offline_threshold))
                offline = total - online
                
                # 按设备类型统计
                type_stats = {}
                for device in devices.values():
                    device_type = device.get('device_type', 'unknown')
                    type_stats[device_type] = type_stats.get(device_type, 0) + 1
                
                return jsonify({
                    'success': True,
                    'stats': {
                        'total': total,
                        'online': online,
                        'offline': offline,
                        'by_type': type_stats
                    }
                })
            except Exception as e:
                logger.error(f"获取设备统计失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        # ==================== 威胁记录API ====================
        
        @self.app.route('/api/threats')
        @login_required
        def api_get_threats():
            """获取威胁记录"""
            try:
                page = int(request.args.get('page', 1))
                per_page = int(request.args.get('per_page', 20))
                severity = request.args.get('severity', None)
                threat_type = request.args.get('type', None)
                
                # 获取威胁记录
                threats = self.database.get_threats(
                    limit=per_page,
                    offset=(page - 1) * per_page,
                    severity=severity,
                    threat_type=threat_type
                )
                
                # 获取总数
                total = self.database.get_threats_count(
                    severity=severity,
                    threat_type=threat_type
                )
                
                return jsonify({
                    'success': True,
                    'threats': threats,
                    'pagination': {
                        'page': page,
                        'per_page': per_page,
                        'total': total,
                        'pages': (total + per_page - 1) // per_page
                    }
                })
            except Exception as e:
                logger.error(f"获取威胁记录失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/threats/stats')
        @login_required
        def api_get_threat_stats():
            """获取威胁统计"""
            try:
                # 获取最近7天的威胁统计
                stats = self.database.get_threat_stats(days=7)
                
                return jsonify({
                    'success': True,
                    'stats': stats
                })
            except Exception as e:
                logger.error(f"获取威胁统计失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/threats/<int:threat_id>')
        @login_required
        def api_get_threat_detail(threat_id):
            """获取威胁详情"""
            try:
                threat = self.database.get_threat_by_id(threat_id)
                
                if not threat:
                    return jsonify({'success': False, 'message': '威胁记录不存在'}), 404
                
                return jsonify({
                    'success': True,
                    'threat': threat
                })
            except Exception as e:
                logger.error(f"获取威胁详情失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/threats/<int:threat_id>', methods=['DELETE'])
        @login_required
        def api_delete_threat(threat_id):
            """删除威胁记录"""
            try:
                success = self.database.delete_threat(threat_id)
                
                if success:
                    return jsonify({
                        'success': True,
                        'message': '威胁记录已删除'
                    })
                else:
                    return jsonify({'success': False, 'message': '删除失败'}), 400
            except Exception as e:
                logger.error(f"删除威胁记录失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/threats/clear', methods=['POST'])
        @login_required
        def api_clear_threats():
            """清除所有威胁记录"""
            try:
                success = self.database.delete_all_threats()
                
                if success:
                    logger.info("所有威胁记录已清除")
                    return jsonify({
                        'success': True,
                        'message': '所有威胁记录已清除'
                    })
                else:
                    return jsonify({'success': False, 'message': '清除失败'}), 400
            except Exception as e:
                logger.error(f"清除威胁记录失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/threats/notification-settings')
        @login_required
        def api_get_threat_notification_settings():
            """获取威胁通知设置"""
            try:
                settings = {}
                threat_types = ['unknown_device', 'behavior_anomaly', 'suspicious_port', 'bandwidth_anomaly', 'nas_external_access', 'self_external_access']
                
                for threat_type in threat_types:
                    enabled = self.database.get_system_status(
                        f'NOTIFY_{threat_type}',
                        'true'
                    )
                    settings[threat_type] = enabled.lower() == 'true'
                
                return jsonify({
                    'success': True,
                    'settings': settings
                })
            except Exception as e:
                logger.error(f"获取威胁通知设置失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/threats/notification-settings', methods=['POST'])
        @login_required
        def api_update_threat_notification_settings():
            """更新威胁通知设置"""
            try:
                data = request.get_json()
                settings = data.get('settings', {})
                
                for threat_type, enabled in settings.items():
                    self.database.set_system_status(
                        f'NOTIFY_{threat_type}',
                        'true' if enabled else 'false'
                    )
                
                logger.info(f"威胁通知设置已更新: {settings}")
                return jsonify({
                    'success': True,
                    'message': '通知设置已更新'
                })
            except Exception as e:
                logger.error(f"更新威胁通知设置失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/settings/ml')
        @login_required
        def api_get_ml_settings():
            """获取ML设置"""
            try:
                ml_available = True
                try:
                    from ..ml.risk_enhancer import MLRiskEnhancer
                    from ..ml.behavior_detector import MLBehaviorDetector
                except ImportError:
                    ml_available = False
                
                risk_model_trained = False
                behavior_model_trained = False
                behavior_samples = 0
                
                if ml_available:
                    risk_meta = self.database.get_ml_model_metadata('risk_classifier')
                    risk_model_trained = risk_meta is not None and risk_meta.get('training_samples', 0) >= 10
                    
                    total_devices = self.database.get_total_devices_count()
                    behavior_samples = self.database.get_devices_with_sufficient_behavior_data(min_observations=2)
                    
                    if total_devices < 10:
                        behavior_threshold = max(5, int(total_devices * 0.5))
                    elif total_devices <= 50:
                        behavior_threshold = max(10, min(int(total_devices * 0.5), 30))
                    else:
                        behavior_threshold = max(15, min(int(total_devices * 0.5), 50))
                    
                    behavior_model_trained = behavior_samples >= behavior_threshold
                
                return jsonify({
                    'success': True,
                    'settings': {
                        'enable_ml_risk': self.config.get_bool('ENABLE_ML_RISK', True),
                        'enable_ml_behavior': self.config.get_bool('ENABLE_ML_BEHAVIOR', True),
                        'ml_risk_model': self.config.get('ML_RISK_MODEL', 'sklearn_rf'),
                        'ml_behavior_model': self.config.get('ML_BEHAVIOR_MODEL', 'sklearn_if'),
                        'ml_library_available': ml_available,
                        'risk_model_trained': risk_model_trained,
                        'behavior_model_trained': behavior_model_trained,
                        'behavior_samples': behavior_samples,
                        'device_count': total_devices
                    }
                })
            except Exception as e:
                logger.error(f"获取ML设置失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/settings/ml', methods=['POST'])
        @login_required
        def api_save_ml_settings():
            """保存ML设置"""
            try:
                data = request.get_json()
                settings = data.get('settings', {})
                
                config_file = self.config.config_file
                
                config_lines = []
                if os.path.exists(config_file):
                    with open(config_file, 'r', encoding='utf-8') as f:
                        config_lines = f.readlines()
                
                settings_to_save = {
                    'ENABLE_ML_RISK': str(settings.get('enable_ml_risk', True)).lower(),
                    'ENABLE_ML_BEHAVIOR': str(settings.get('enable_ml_behavior', True)).lower(),
                    'ML_RISK_MODEL': settings.get('ml_risk_model', 'sklearn_rf'),
                    'ML_BEHAVIOR_MODEL': settings.get('ml_behavior_model', 'sklearn_if')
                }
                
                existing_keys = set()
                new_lines = []
                for line in config_lines:
                    stripped = line.strip()
                    key_found = False
                    for key in settings_to_save:
                        if stripped.startswith(f'{key}='):
                            new_lines.append(f'{key}={settings_to_save[key]}\n')
                            existing_keys.add(key)
                            key_found = True
                            break
                    if not key_found:
                        new_lines.append(line)
                
                for key, value in settings_to_save.items():
                    if key not in existing_keys:
                        new_lines.append(f'{key}={value}\n')
                
                with open(config_file, 'w', encoding='utf-8') as f:
                    f.writelines(new_lines)
                
                self.config._load_config()
                
                logger.info(f"ML设置已更新: {settings_to_save}")
                return jsonify({
                    'success': True,
                    'message': 'ML设置已保存，重启服务后生效'
                })
            except Exception as e:
                logger.error(f"保存ML设置失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/settings/auto-block', methods=['GET'])
        @login_required
        def api_get_auto_block_settings():
            """获取自动封禁设置"""
            try:
                auto_block_enabled = self.config.get_bool('AUTO_BLOCK_ENABLED', False)
                auto_block_threshold = self.config.get_int('AUTO_BLOCK_THRESHOLD', 80)
                
                return jsonify({
                    'success': True,
                    'settings': {
                        'auto_block_enabled': auto_block_enabled,
                        'auto_block_threshold': auto_block_threshold
                    }
                })
            except Exception as e:
                logger.error(f"获取自动封禁设置失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/settings/auto-block', methods=['POST'])
        @login_required
        def api_save_auto_block_settings():
            """保存自动封禁设置"""
            try:
                data = request.get_json()
                settings = data.get('settings', {})
                
                config_file = self.config.config_file
                
                config_lines = []
                if os.path.exists(config_file):
                    with open(config_file, 'r', encoding='utf-8') as f:
                        config_lines = f.readlines()
                
                settings_to_save = {
                    'AUTO_BLOCK_ENABLED': str(settings.get('auto_block_enabled', False)).lower(),
                    'AUTO_BLOCK_THRESHOLD': str(settings.get('auto_block_threshold', 80))
                }
                
                existing_keys = set()
                new_lines = []
                for line in config_lines:
                    stripped = line.strip()
                    key_found = False
                    for key in settings_to_save:
                        if stripped.startswith(f'{key}='):
                            new_lines.append(f'{key}={settings_to_save[key]}\n')
                            existing_keys.add(key)
                            key_found = True
                            break
                    if not key_found:
                        new_lines.append(line)
                
                for key, value in settings_to_save.items():
                    if key not in existing_keys:
                        new_lines.append(f'{key}={value}\n')
                
                with open(config_file, 'w', encoding='utf-8') as f:
                    f.writelines(new_lines)
                
                self.config._load_config()
                
                logger.info(f"自动封禁设置已更新: {settings_to_save}")
                return jsonify({
                    'success': True,
                    'message': '自动封禁设置已保存'
                })
            except Exception as e:
                logger.error(f"保存自动封禁设置失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        # ==================== 系统状态API ====================
        
        @self.app.route('/api/system/status')
        @login_required
        def api_get_system_status():
            """获取系统状态"""
            try:
                first_run_status = self.database.get_first_run_status()
                device_count = self.database.get_total_devices_count()
                threat_count = self.database.get_threats_count()
                last_check_time = self.database.get_last_check_time()
                
                return jsonify({
                    'success': True,
                    'status': {
                        'first_run': first_run_status,
                        'device_count': device_count,
                        'threat_count': threat_count,
                        'last_check_time': last_check_time
                    }
                })
            except Exception as e:
                logger.error(f"获取系统状态失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/system/learning-status')
        @login_required
        def api_get_learning_status():
            """获取学习期状态"""
            try:
                status = self.database.get_first_run_status()
                
                return jsonify({
                    'success': True,
                    'status': status
                })
            except Exception as e:
                logger.error(f"获取学习期状态失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/system/reset-learning', methods=['POST'])
        @login_required
        def api_reset_learning():
            """重置学习期状态"""
            try:
                self.database.reset_first_run()
                logger.info("学习期状态已重置")
                
                return jsonify({
                    'success': True,
                    'message': '学习期已重置，系统将重新开始学习设备行为'
                })
            except Exception as e:
                logger.error(f"重置学习期失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/system/change-password', methods=['POST'])
        @login_required
        def api_change_password():
            """修改密码"""
            try:
                data = request.get_json()
                current_password = data.get('current_password')
                new_username = data.get('new_username')
                new_password = data.get('new_password')
                
                web_password = self.database.get_system_status('WEB_PASSWORD', 
                    self.config.get('WEB_PASSWORD', 'admin123'))
                
                if current_password != web_password:
                    return jsonify({'success': False, 'message': '当前密码错误'}), 400
                
                if new_username:
                    self.database.set_system_status('WEB_USERNAME', new_username)
                if new_password:
                    self.database.set_system_status('WEB_PASSWORD', new_password)
                
                logger.info("用户凭证已更新")
                return jsonify({
                    'success': True,
                    'message': '凭证修改成功，请重新登录'
                })
            except Exception as e:
                logger.error(f"修改密码失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/devices/<mac>/mark', methods=['POST'])
        @login_required
        def api_mark_device(mac):
            """标记设备类型"""
            try:
                data = request.get_json()
                device_type = data.get('device_type')
                vendor = data.get('vendor')
                notes = data.get('notes', '')
                
                if not device_type:
                    return jsonify({'success': False, 'message': '设备类型不能为空'}), 400
                
                devices = self.database.load_known_devices()
                if mac not in devices:
                    return jsonify({'success': False, 'message': '设备不存在'}), 404
                
                device = devices[mac]
                device['device_type'] = device_type
                if vendor:
                    device['vendor'] = vendor
                if notes:
                    device['notes'] = notes
                
                self.database.save_device(device)
                
                if device_type == 'nas':
                    mac_upper = mac.upper()
                    if not Config.validate_mac(mac_upper):
                        logger.warning(f"MAC地址格式无效: {mac}")
                    else:
                        nas_devices = self.config.get_list('NAS_DEVICES', [])
                        if mac_upper not in nas_devices:
                            nas_devices.append(mac_upper)
                            success = self.config.set('NAS_DEVICES', ','.join(nas_devices))
                            if success:
                                logger.info(f"NAS设备 {mac} 已添加到监控列表")
                            else:
                                logger.warning(f"添加NAS设备失败: {mac}")
                
                logger.info(f"设备 {mac} 已标记为 {device_type}")
                
                return jsonify({
                    'success': True,
                    'message': f'设备已标记为 {device_type}'
                })
            except Exception as e:
                logger.error(f"标记设备失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/trust-port', methods=['POST'])
        @login_required
        def api_trust_port():
            """添加信任端口到配置"""
            try:
                data = request.get_json()
                ip = data.get('ip')
                port = data.get('port')
                
                if not ip or not port:
                    return jsonify({'success': False, 'message': '缺少IP或端口参数'}), 400
                
                port = int(port)
                if port < 1 or port > 65535:
                    return jsonify({'success': False, 'message': '端口号无效'}), 400
                
                trusted_key = f"{ip}:{port}"
                trusted_ports = self.config.get_list('TRUSTED_NAS_PORTS', [])
                
                if trusted_key not in trusted_ports:
                    trusted_ports.append(trusted_key)
                    success = self.config.set('TRUSTED_NAS_PORTS', ','.join(trusted_ports))
                    if success:
                        logger.info(f"已添加信任端口: {trusted_key}")
                    else:
                        return jsonify({'success': False, 'message': '保存配置失败'}), 500
                else:
                    logger.info(f"端口 {trusted_key} 已在信任列表中")
                
                return jsonify({
                    'success': True,
                    'message': f'端口 {trusted_key} 已添加到信任列表'
                })
            except Exception as e:
                logger.error(f"添加信任端口失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/blocked-devices', methods=['GET'])
        @login_required
        def api_get_blocked_devices():
            """获取封禁设备列表"""
            try:
                active_only = request.args.get('active_only', 'true').lower() == 'true'
                blocked_devices = self.database.get_blocked_devices(active_only=active_only)
                return jsonify({
                    'success': True,
                    'blocked_devices': blocked_devices
                })
            except Exception as e:
                logger.error(f"获取封禁设备失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/devices/<mac>/block', methods=['POST'])
        @login_required
        def api_block_device(mac):
            """手动封禁设备"""
            try:
                data = request.get_json()
                reason = data.get('reason', '手动封禁')
                auto_unblock_hours = data.get('auto_unblock_hours')
                
                devices = self.database.load_all_devices()
                device = devices.get(mac)
                
                if not device:
                    return jsonify({'success': False, 'message': '设备不存在'}), 404
                
                self.database.block_device(
                    mac=mac,
                    ip=device.get('ip'),
                    vendor=device.get('vendor'),
                    reason=reason,
                    block_type='manual',
                    blocked_by='manual',
                    auto_unblock_hours=auto_unblock_hours
                )
                
                from ..utils.ikuai_api import IKuaiAPI
                from ..utils.config import Config
                ikuai = IKuaiAPI(Config(), self.secure_config if hasattr(self, 'secure_config') else None)
                ikuai.add_device_to_blacklist(
                    mac=mac,
                    ip=device.get('ip', ''),
                    reason=f"手动封禁: {reason}"
                )
                
                logger.info(f"设备 {mac} 已手动封禁")
                return jsonify({'success': True, 'message': '设备已封禁'})
            except Exception as e:
                logger.error(f"封禁设备失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/devices/<mac>/unblock', methods=['POST'])
        @login_required
        def api_unblock_device(mac):
            """手动解禁设备"""
            try:
                data = request.get_json()
                notes = data.get('notes', '')
                
                self.database.unblock_device(mac, unblocked_by='manual', notes=notes)
                
                from ..utils.ikuai_api import IKuaiAPI
                from ..utils.config import Config
                ikuai = IKuaiAPI(Config(), self.secure_config if hasattr(self, 'secure_config') else None)
                ikuai.remove_device_from_blacklist(mac)
                
                logger.info(f"设备 {mac} 已手动解禁")
                return jsonify({'success': True, 'message': '设备已解禁'})
            except Exception as e:
                logger.error(f"解禁设备失败: {str(e)}")
                return jsonify({'success': False, 'message': str(e)}), 500
    
    def _is_device_online(self, last_seen: str, threshold_seconds: int = 600) -> bool:
        """判断设备是否在线
        
        Args:
            last_seen: 最后看到时间（ISO格式字符串）
            threshold_seconds: 离线阈值（秒）
            
        Returns:
            是否在线
        """
        if not last_seen:
            return False
        
        try:
            last_seen_time = datetime.fromisoformat(last_seen)
            time_diff = datetime.now() - last_seen_time
            return time_diff.total_seconds() <= threshold_seconds
        except (ValueError, TypeError):
            return False
    
    def run(self, host='0.0.0.0', port=5000, debug=False):
        """运行Web应用"""
        logger.info(f"启动Web应用: http://{host}:{port}")
        self.app.run(host=host, port=port, debug=debug, threaded=True)


def create_app():
    """创建Flask应用"""
    config = Config()
    database = Database(config)
    web_app = WebApp(config, database)
    return web_app.app


if __name__ == '__main__':
    config = Config()
    database = Database(config)
    web_app = WebApp(config, database)
    
    # 从配置读取端口
    port = config.get_int('WEB_PORT', 5000)
    debug = config.get_bool('WEB_DEBUG', False)
    
    web_app.run(port=port, debug=debug)
