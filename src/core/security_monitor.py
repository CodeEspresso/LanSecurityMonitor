#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全监控核心类
"""

import time
import logging
from typing import Dict, List, Any
from datetime import datetime

from ..monitors.network_scanner import NetworkScanner
from ..monitors.threat_detector import ThreatDetector
from ..monitors.device_analyzer import DeviceAnalyzer
from ..monitors.nas_monitor import NASMonitor
from ..monitors.behavior_analyzer import BehaviorAnalyzer
from ..monitors.bandwidth_monitor import BandwidthMonitor
from ..monitors.arp_monitor import ARPMonitor
from ..monitors.dns_monitor import DNSMonitor
from ..monitors.device_correlator import DeviceCorrelator
from ..notifiers.bark_notifier import BarkNotifier
from ..utils.database import Database
from ..utils.metrics_exporter import MetricsExporter
from ..utils.ikuai_api import IKuaiAPI
from ..utils.device_utils import DeviceUtils


class SecurityMonitor:
    """安全监控核心类"""
    
    def __init__(self, config, secure_config=None):
        self.config = config
        self.secure_config = secure_config
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        # 初始化组件
        self.database = Database(config)
        self.network_scanner = NetworkScanner(config, self.database)
        self.threat_detector = ThreatDetector(config, self.database)
        self.device_analyzer = DeviceAnalyzer(config)
        self.nas_monitor = NASMonitor(config)
        self.bark_notifier = BarkNotifier(config, secure_config)
        self.behavior_analyzer = BehaviorAnalyzer(config, self.database)
        self.bandwidth_monitor = BandwidthMonitor(config)
        self.metrics_exporter = MetricsExporter(config, self.database)
        self.ikuai_api = IKuaiAPI(config, secure_config)
        self.arp_monitor = ARPMonitor(config, self.database)
        self.dns_monitor = DNSMonitor(config, secure_config)
        self.device_correlator = DeviceCorrelator(config, self.database)
        
        # 状态存储
        self.known_devices = {}
        self.alert_history = []
    
    def initialize(self):
        """初始化监控系统"""
        self.logger.info("初始化监控系统...")
        
        # 检查是否为首次运行
        is_first_run = self.database.is_first_run()
        
        if is_first_run:
            self.logger.info("=" * 60)
            self.logger.info("🎉 检测到首次运行（学习期）")
            self.logger.info("=" * 60)
            self.logger.info("系统将自动调整通知策略以避免通知爆炸")
            self.logger.info("⚠️  学习期安全策略：")
            self.logger.info("   ✅ 严重威胁通知: 保持开启（high/critical级别）")
            self.logger.info("   ⏸️  中等威胁通知: 暂时关闭（避免误报）")
            self.logger.info("   ⏸️  新设备通知: 暂时关闭")
            self.logger.info("   ⏸️  行为分析通知: 暂时关闭")
            self.logger.info("   ⏸️  带宽监控通知: 暂时关闭")
            self.logger.info("   ⏸️  首次出现告警: 暂时关闭")
            self.logger.info("")
            self.logger.info("📚 学习期要求：")
            self.logger.info("   • 行为观察数据时间范围 >= 24小时")
            self.logger.info("   • 有足够观察数据的设备 >= 设备总数的50%")
            self.logger.info("=" * 60)
            
            # 首次运行时，自动调整通知策略
            self._adjust_notification_strategy_for_first_run()
        
        # 加载已知设备
        self.known_devices = self.database.load_known_devices()
        self.logger.info(f"已加载 {len(self.known_devices)} 个已知设备")
        
        # 初始化网络扫描器
        self.network_scanner.initialize()
        
        # 初始化威胁检测器
        self.threat_detector.initialize()
        
        # 初始化NAS监控器
        self.nas_monitor.initialize()
        
        # 初始化行为分析器
        self.behavior_analyzer.initialize()
        
        # 初始化带宽监控器
        self.bandwidth_monitor.initialize()
        
        # 初始化指标导出器
        self.metrics_exporter.initialize()
        
        # 初始化爱快路由器API
        self.ikuai_api.initialize()
        
        # 初始化ARP监控器
        self.arp_monitor.initialize()
        
        # 初始化DNS监控器
        self.dns_monitor.initialize()
        
        # 初始化设备关联器
        self.device_correlator.initialize()
        
        self.logger.info("监控系统初始化完成")
    
    def run_security_check(self):
        """执行安全检查"""
        check_start_time = time.time()
        self.logger.info("开始安全检查...")
        
        try:
            # 1. 扫描局域网设备
            self.logger.info("步骤1: 扫描局域网设备...")
            current_devices = self.network_scanner.scan_network()
            self.logger.info(f"发现 {len(current_devices)} 个设备")
            
            # 2. 检测新设备和离线设备
            self.logger.info("步骤2: 检测设备变化...")
            new_devices, offline_devices = self._detect_device_changes(current_devices)
            
            if new_devices:
                self.logger.warning(f"发现 {len(new_devices)} 个新设备")
                self._handle_new_devices(new_devices)
            
            if offline_devices:
                self.logger.info(f"发现 {len(offline_devices)} 个设备离线")
            
            # 3. ARP绑定检测（新增）
            self.logger.info("步骤3: ARP绑定检测...")
            arp_anomalies = self._detect_arp_anomalies(current_devices)
            
            if arp_anomalies:
                self.logger.warning(f"发现 {len(arp_anomalies)} 个ARP绑定异常")
                self._handle_arp_anomalies(arp_anomalies)
            
            # 4. 威胁检测
            self.logger.info("步骤4: 执行威胁检测...")
            threats = self.threat_detector.detect_threats(current_devices, self.known_devices)
            
            if threats:
                self.logger.warning(f"发现 {len(threats)} 个潜在威胁")
                self._handle_threats(threats)
            
            # 5. 深度分析可疑设备
            self.logger.info("步骤5: 深度分析可疑设备...")
            suspicious_devices = [t['device'] for t in threats if t.get('severity') == 'high']
            
            if suspicious_devices:
                analysis_results = self.device_analyzer.analyze_devices(suspicious_devices)
                self._handle_analysis_results(analysis_results)
            
            # 6. NAS设备监控
            self.logger.info("步骤6: NAS设备监控...")
            nas_anomalies = self.nas_monitor.monitor_nas_devices(current_devices)
            
            if nas_anomalies:
                self.logger.warning(f"发现 {len(nas_anomalies)} 个NAS异常")
                for anomaly in nas_anomalies:
                    self._handle_threats([anomaly])
            
            # 6.5 本机外网连接监控
            self.logger.info("步骤6.5: 本机外网连接监控...")
            self_anomalies = self.nas_monitor.monitor_self()
            
            if self_anomalies:
                self.logger.warning(f"发现 {len(self_anomalies)} 个本机异常连接")
                for anomaly in self_anomalies:
                    self._handle_threats([anomaly])
            
            # 7. 设备行为分析
            self.logger.info("步骤7: 设备行为分析...")
            behavior_anomalies = self.behavior_analyzer.analyze_device_behavior(current_devices)
            
            if behavior_anomalies:
                self.logger.warning(f"发现 {len(behavior_anomalies)} 个行为异常")
                for anomaly in behavior_anomalies:
                    self._handle_threats([anomaly])
            
            # 8. 带宽使用监控
            self.logger.info("步骤8: 带宽使用监控...")
            bandwidth_anomalies = self.bandwidth_monitor.monitor_bandwidth(current_devices)
            
            if bandwidth_anomalies:
                self.logger.warning(f"发现 {len(bandwidth_anomalies)} 个带宽异常")
                for anomaly in bandwidth_anomalies:
                    self._handle_threats([anomaly])
            
            # 9. DNS监控（DGA检测、恶意域名）
            self.logger.info("步骤9: DNS监控...")
            dns_threats = self.dns_monitor.check()
            
            if dns_threats:
                self.logger.warning(f"发现 {len(dns_threats)} 个DNS威胁")
                for threat in dns_threats:
                    self._handle_threats([threat])
            
            # 10. 更新设备状态
            self.logger.info("步骤10: 更新设备状态...")
            self._update_device_status(current_devices)
            
            # 10. 检查是否应该退出首次运行模式
            self._check_and_exit_first_run_mode()
            
            # 11. 保存检查结果
            self.database.save_check_result({
                'timestamp': datetime.now().isoformat(),
                'total_devices': len(current_devices),
                'new_devices': len(new_devices),
                'offline_devices': len(offline_devices),
                'threats': len(threats) + len(nas_anomalies) + len(behavior_anomalies) + len(bandwidth_anomalies),
                'check_duration': time.time() - check_start_time
            })
            
            self.logger.info(f"安全检查完成，耗时: {time.time() - check_start_time:.2f}秒")
            
        except Exception as e:
            self.logger.error(f"安全检查失败: {str(e)}", exc_info=True)
            raise
    
    def _detect_arp_anomalies(self, current_devices: Dict) -> List[Dict]:
        """检测ARP绑定异常
        
        Args:
            current_devices: 当前设备字典
            
        Returns:
            ARP异常列表
        """
        self.arp_monitor.refresh_arp_table()
        
        anomalies = []
        
        for mac, device in current_devices.items():
            ip = device.get('ip')
            if not ip:
                continue
            
            binding_result = self.arp_monitor.check_binding_changes(ip, mac)
            
            if not binding_result['is_normal']:
                anomalies.append({
                    'type': 'arp_binding_anomaly',
                    'severity': 'high',
                    'device': device,
                    'device_ip': ip,
                    'device_mac': mac,
                    'description': binding_result['details'],
                    'risk_score': binding_result['risk_score'],
                    'anomaly_type': binding_result['anomaly_type']
                })
            
            if not device.get('ip'):
                continue
            
            mac_flapping = self.arp_monitor.detect_mac_flapping(mac)
            if mac_flapping['is_flapping']:
                anomalies.append({
                    'type': 'mac_flapping',
                    'severity': 'high',
                    'device': device,
                    'device_ip': ip,
                    'device_mac': mac,
                    'description': f"MAC地址 {mac} 在短时间内变化 {mac_flapping['change_count']} 次，可能存在MAC欺骗",
                    'risk_score': mac_flapping['risk_score']
                })
        
        return anomalies
    
    def _handle_arp_anomalies(self, anomalies: List[Dict]):
        """处理ARP异常
        
        Args:
            anomalies: ARP异常列表
        """
        auto_block_enabled = self.config.get_bool('AUTO_BLOCK_ENABLED', False)
        auto_block_threshold = self.config.get_int('AUTO_BLOCK_THRESHOLD', 80)
        
        for anomaly in anomalies:
            device = anomaly.get('device', {})
            ip = device.get('ip', '')
            mac = device.get('mac', '')
            description = anomaly.get('description', '')
            risk_score = anomaly.get('risk_score', 0)
            
            self.logger.warning(f"ARP异常: {description}")
            
            self.database.save_threat({
                'type': anomaly.get('type', 'arp_anomaly'),
                'severity': anomaly.get('severity', 'high'),
                'device': device,
                'description': description
            })
            
            if auto_block_enabled and risk_score >= auto_block_threshold:
                if not self.database.is_device_blocked(mac):
                    self.logger.warning(f"自动封禁高风险设备: {ip} ({mac}), 风险评分: {risk_score}")
                    self._auto_block_device(device, description, risk_score)
                else:
                    self.logger.info(f"设备 {mac} 已在封禁中")
            
            notify_enabled = self._is_notification_enabled('arp_anomaly')
            if notify_enabled:
                self.bark_notifier.send_alert(
                    title=f"⚠️ ARP绑定异常 - {anomaly.get('type', 'arp')}",
                    message=f"设备: {ip} ({mac})\n风险评分: {risk_score}\n详情: {description}",
                    severity='high',
                    device=device,
                    is_threat=True
                )
    
    def _auto_block_device(self, device: Dict, reason: str, risk_score: int):
        """自动封禁设备
        
        Args:
            device: 设备信息
            reason: 封禁原因
            risk_score: 风险评分
        """
        mac = device.get('mac')
        ip = device.get('ip', '')
        vendor = device.get('vendor', '')
        
        full_reason = f"{reason} (风险评分: {risk_score})"
        
        self.database.block_device(
            mac=mac,
            ip=ip,
            vendor=vendor,
            reason=full_reason,
            block_type='auto',
            blocked_by='system'
        )
        
        success = self.ikuai_api.add_device_to_blacklist(
            mac=mac,
            ip=ip,
            reason=f"安全监控自动封禁 - {reason}"
        )
        
        if success:
            self.bark_notifier.send_alert(
                title="🔒 设备已自动封禁",
                message=f"设备 {ip} ({mac}) 因风险评分过高已被自动封禁\n原因: {full_reason}",
                severity='critical',
                device=device,
                is_threat=True
            )
        else:
            self.logger.error(f"自动封禁设备失败: {ip} ({mac})")
    
    def _detect_device_changes(self, current_devices: Dict) -> tuple:
        """检测设备变化"""
        new_devices = []
        offline_devices = []
        
        current_macs = set(current_devices.keys())
        known_macs = set(self.known_devices.keys())
        
        # 检测离线设备（先检测离线，再处理新设备）
        for mac in known_macs - current_macs:
            offline_device = self.known_devices[mac]
            offline_devices.append(offline_device)
            # 记录设备下线，供设备关联器使用
            self.device_correlator.record_device_offline(offline_device)
        
        # 检测新设备
        for mac in current_macs - known_macs:
            # 检查是否是MAC随机化的同一设备
            correlation_result = self.device_correlator.check_device_reappeared(current_devices[mac])
            
            if correlation_result and correlation_result.get('is_same_device'):
                # 是同一设备（MAC随机化），不作为新设备处理
                original_mac = correlation_result.get('original_mac')
                similarity = correlation_result.get('similarity', 0)
                self.logger.info(
                    f"设备 {current_devices[mac].get('ip')} 判断为同一设备(MAC随机化): "
                    f"新MAC={mac}, 原MAC={original_mac}, 相似度={similarity:.1%}"
                )
                # 继承原设备的信息
                if original_mac in self.known_devices:
                    original_device = self.known_devices[original_mac]
                    current_devices[mac]['inherited_info'] = {
                        'original_mac': original_mac,
                        'similarity': similarity,
                        'device_type': original_device.get('device_type'),
                        'vendor': original_device.get('vendor'),
                        'hostname': original_device.get('hostname'),
                        'category': original_device.get('category')
                    }
            else:
                # 确实是新设备
                new_devices.append(current_devices[mac])
        
        return new_devices, offline_devices
    
    def _handle_new_devices(self, new_devices: List[Dict]):
        """处理新设备"""
        for device in new_devices:
            mac = device.get('mac')
            ip = device.get('ip')
            hostname = device.get('hostname', 'Unknown')
            
            message = f"发现新设备\nIP: {ip}\nMAC: {mac}\n主机名: {hostname}"
            self.logger.warning(message)
            
            # 检查是否在首次运行模式
            if hasattr(self, '_first_run_mode') and self._first_run_mode:
                self.logger.info(f"首次运行模式：设备 {mac} 已记录，将进行安全检查")
                self.logger.info(f"⚠️  如果该设备存在威胁，将会收到威胁通知")
            else:
                # 非首次运行模式，分析设备类型
                analyzed_device = DeviceUtils.analyze_device(device.copy(), self.database)
                detected_type = analyzed_device.get('device_type', 'unknown')
                
                # 检测到NAS设备，提醒用户确认
                if detected_type == 'nas':
                    nas_devices = self.config.get_list('NAS_DEVICES', [])
                    mac_upper = mac.upper()
                    if mac_upper not in nas_devices:
                        self.logger.info(f"检测到新NAS设备: {hostname}({ip})")
                        message_nas = (
                            f"🔔 检测到新NAS设备\n"
                            f"IP: {ip}\n"
                            f"MAC: {mac}\n"
                            f"主机名: {hostname}\n\n"
                            f"请在Web界面标记该设备为NAS以启用外网访问监控"
                        )
                        self.bark_notifier.send_alert(
                            title="🔔 新NAS设备 detected",
                            message=message_nas,
                            severity='warning',
                            device=device
                        )
                
                # 发送普通新设备通知
                self.bark_notifier.send_alert(
                    title="🚨 新设备接入",
                    message=message,
                    severity='warning',
                    device=device
                )
            
            # 保存到数据库
            self.database.save_device(device)
    
    def _handle_threats(self, threats: List[Dict]):
        """处理威胁"""
        # 检查是否应该跳过通知（学习期或有足够数据前）
        should_suppress_notifications = False
        if hasattr(self, '_first_run_mode') and self._first_run_mode:
            should_suppress_notifications = True
        else:
            # 检查是否有足够的学习数据
            total_behaviors = self.database.get_total_behavior_count()
            if total_behaviors < 100:
                should_suppress_notifications = True
        
        for threat in threats:
            device = threat.get('device', {})
            threat_type = threat.get('type', 'unknown')
            severity = threat.get('severity', 'low')
            description = threat.get('description', '')
            
            message = f"威胁类型: {threat_type}\n严重程度: {severity}\n设备: {device.get('ip')}\n描述: {description}"
            self.logger.warning(message)
            
            notify_enabled = self._is_notification_enabled(threat_type)
            
            if not notify_enabled:
                self.logger.info(f"通知已禁用，跳过威胁通知: {threat_type}")
            
            elif should_suppress_notifications and threat_type in ['behavior_anomaly', 'bandwidth_anomaly', 'new_device']:
                # 学习期或数据不足时，跳过行为/带宽/新设备通知
                self.logger.info(f"学习期/数据不足：跳过 {threat_type} 通知")
            
            elif should_suppress_notifications and severity in ['high', 'critical']:
                self.logger.warning(f"学习期检测到严重威胁: {threat_type} ({severity})")
                self.bark_notifier.send_alert(
                    title=f"⚠️ 严重安全威胁 - {threat_type}",
                    message=message,
                    severity=severity,
                    device=device,
                    is_threat=True
                )
            elif should_suppress_notifications:
                self.logger.info(f"学习期：跳过中等威胁通知 ({threat_type}, {severity})")
            else:
                self.bark_notifier.send_alert(
                    title=f"⚠️ 安全威胁 - {threat_type}",
                    message=message,
                    severity=severity,
                    device=device,
                    is_threat=True
                )
            
            # 高危DNS威胁自动隔离
            if severity in ['critical', 'high'] and device:
                enable_auto_isolate = self.config.get_bool('ENABLE_AUTO_ISOLATE', False)
                if enable_auto_isolate:
                    self.logger.critical(f"高风险威胁: {threat_type}, 准备隔离设备 {device.get('ip')}")
                    self._isolate_device(device)
            
            self.database.save_threat(threat)
    
    def _is_notification_enabled(self, threat_type: str) -> bool:
        """检查威胁类型是否启用通知
        
        Args:
            threat_type: 威胁类型
            
        Returns:
            是否启用通知
        """
        try:
            enabled = self.database.get_system_status(
                f'NOTIFY_{threat_type}',
                'true'
            )
            return enabled.lower() == 'true'
        except Exception:
            return True
    
    def _handle_analysis_results(self, analysis_results: List[Dict]):
        """处理分析结果"""
        for result in analysis_results:
            device = result.get('device', {})
            risk_level = result.get('risk_level', 'unknown')
            recommendations = result.get('recommendations', [])
            
            if risk_level == 'critical':
                # 高风险设备，采取隔离措施
                self.logger.critical(f"高风险设备: {device.get('ip')}, 准备隔离")
                self._isolate_device(device)
            
            message = f"风险等级: {risk_level}\n设备: {device.get('ip')}\n建议: {', '.join(recommendations)}"
            self.bark_notifier.send_alert(
                title="🔍 设备分析结果",
                message=message,
                severity='high' if risk_level in ['critical', 'high'] else 'medium',
                device=device,
                is_threat=(risk_level in ['critical', 'high'])
            )
    
    def _isolate_device(self, device: Dict):
        """隔离设备（限制联网）"""
        ip = device.get('ip')
        mac = device.get('mac')
        
        self.logger.warning(f"正在隔离设备: {ip} ({mac})")
        
        # 使用爱快路由器API添加到黑名单
        success = self.ikuai_api.add_device_to_blacklist(
            mac=mac,
            ip=ip,
            reason=f"安全监控自动封禁 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        
        if success:
            # 发送Bark通知
            self.bark_notifier.send_alert(
                title="🔒 设备已隔离",
                message=f"设备 {ip} ({mac}) 已被限制联网",
                severity='critical',
                device=device,
                is_threat=True
            )
        else:
            self.logger.error(f"设备隔离失败: {ip} ({mac})")
    def _update_device_status(self, current_devices: Dict):
        """更新设备状态"""
        for mac, device in current_devices.items():
            # 如果是已知设备，先从数据库获取用户手动设置的字段
            if self.database:
                try:
                    old_device = self.database.load_device_by_mac(mac)
                    if old_device:
                        # 保留用户手动设置的字段
                        if old_device.get('hostname') and old_device.get('hostname') not in ('Unknown', 'unknown', ''):
                            device['hostname'] = old_device['hostname']
                        if old_device.get('device_type') and old_device.get('device_type') not in ('unknown', 'Unknown', ''):
                            device['device_type'] = old_device['device_type']
                        if old_device.get('vendor') and old_device.get('vendor') not in ('Unknown', 'unknown', ''):
                            device['vendor'] = old_device['vendor']
                        # 保留 notes 和其他用户设置的字段
                        if old_device.get('notes'):
                            device['notes'] = old_device['notes']
                    else:
                        inherited_info = device.get('inherited_info')
                        if inherited_info:
                            original_mac = inherited_info.get('original_mac')
                            if original_mac:
                                original_device = self.database.load_device_by_mac(original_mac)
                                if original_device:
                                    if inherited_info.get('device_type'):
                                        device['device_type'] = inherited_info['device_type']
                                    if inherited_info.get('vendor'):
                                        device['vendor'] = inherited_info['vendor']
                                    if inherited_info.get('hostname'):
                                        device['hostname'] = inherited_info['hostname']
                                    if inherited_info.get('category'):
                                        device['category'] = inherited_info['category']
                                    device['is_known'] = True
                                    self.logger.info(
                                        f"设备 {mac} 继承了原设备 {original_mac} 的信息 "
                                        f"(相似度: {inherited_info.get('similarity', 0):.1%})"
                                    )
                except Exception as e:
                    self.logger.debug(f"获取设备信息失败: {e}")
            
            if mac in self.known_devices:
                known_device = self.known_devices[mac]
                if known_device.get('is_known', False):
                    device['is_known'] = True
            self.known_devices[mac] = device
            self.database.save_device(device)
    
    def _adjust_notification_strategy_for_first_run(self):
        """首次运行时调整通知策略"""
        # 临时调整通知策略
        original_notify_new_device = self.config.get('NOTIFY_NEW_DEVICE', 'true')
        original_notify_first_seen = self.config.get('NOTIFY_FIRST_SEEN_IMMEDIATELY', 'false')
        
        # 设置为首次运行模式
        self.config._config['NOTIFY_NEW_DEVICE'] = 'false'
        self.config._config['NOTIFY_FIRST_SEEN_IMMEDIATELY'] = 'false'
        
        # 保存原始配置
        self._original_notify_new_device = original_notify_new_device
        self._original_notify_first_seen = original_notify_first_seen
        self._first_run_mode = True
        
        self.logger.info("已启用首次运行模式（通知策略已调整）")
        self.logger.info("- 新设备通知: 已关闭（避免通知爆炸）")
        self.logger.info("- 威胁检测通知: 保持开启（确保安全）")
        self.logger.info("- NAS监控通知: 保持开启（确保安全）")
        self.logger.info("- 行为分析通知: 保持开启（确保安全）")
        self.logger.info("- 带宽监控通知: 保持开启（确保安全）")
    
    def _check_and_exit_first_run_mode(self):
        """检查是否应该退出首次运行模式"""
        if not hasattr(self, '_first_run_mode') or not self._first_run_mode:
            return False
        
        # 检查是否满足退出条件
        # 1. 行为观察数据时间范围 >= 24小时
        earliest_behavior_time = self.database.get_earliest_behavior_time()
        if earliest_behavior_time:
            from datetime import datetime, timedelta
            time_diff = datetime.now() - earliest_behavior_time
            if time_diff < timedelta(hours=24):
                self.logger.info(f"学习期进度: 行为观察数据时间范围 {time_diff} / 24小时")
                return False
        
        # 2. 有足够观察数据的设备 >= 设备总数的50%
        total_devices = self.database.get_total_devices_count()
        devices_with_sufficient_data = self.database.get_devices_with_sufficient_behavior_data(min_observations=7)
        
        if devices_with_sufficient_data < total_devices * 0.5:
            progress = devices_with_sufficient_data / (total_devices * 0.5) * 100
            self.logger.info(f"学习期进度: 有足够观察数据的设备 {devices_with_sufficient_data}/{int(total_devices * 0.5)} ({progress:.1f}%)")
            return False
        
        # 满足退出条件
        self.logger.info("=" * 60)
        self.logger.info("✅ 学习期已完成，退出首次运行模式")
        self.logger.info("=" * 60)
        self.logger.info(f"当前设备数量: {total_devices}")
        self.logger.info(f"有足够观察数据的设备: {devices_with_sufficient_data}")
        
        # 将学习期间记录的所有设备标记为已知设备
        marked_count = self.database.mark_all_devices_as_known()
        self.logger.info(f"已将 {marked_count} 个学习期设备标记为已知")
        
        self.logger.info("恢复原始通知策略:")
        self.logger.info(f"- 新设备通知: {self._original_notify_new_device}")
        self.logger.info(f"- 首次出现告警: {self._original_notify_first_seen}")
        self.logger.info("=" * 60)
        
        # 恢复原始配置
        self.config._config['NOTIFY_NEW_DEVICE'] = self._original_notify_new_device
        self.config._config['NOTIFY_FIRST_SEEN_IMMEDIATELY'] = self._original_notify_first_seen
        
        # 标记首次运行已完成
        self.database.mark_first_run_completed()
        
        # 发送系统通知
        self.bark_notifier.send_alert(
            title="✅ 学习期完成",
            message=f"已学习 {total_devices} 个设备的行为模式，系统已进入正常运行模式",
            severity='info'
        )
        
        self._first_run_mode = False
        return True
    
    def cleanup(self):
        """清理资源"""
        self.logger.info("清理资源...")
        self.network_scanner.cleanup()
        self.nas_monitor.cleanup()
        self.behavior_analyzer.cleanup()
        self.bandwidth_monitor.cleanup()
        self.metrics_exporter.cleanup()
        self.ikuai_api.cleanup()
        self.database.close()
        self.logger.info("资源清理完成")
