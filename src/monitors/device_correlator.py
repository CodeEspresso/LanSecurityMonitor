#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
设备关联器模块
用于检测MAC地址随机化场景下的设备关联
当新设备上线时，对比最近下线的同IP设备行为相似度，判断是否为同一设备
"""

import logging
import time
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger('LanSecurityMonitor')


class DeviceProfile:
    """设备行为画像"""
    
    def __init__(self, mac: str, ip: str, hostname: str = '', device_type: str = ''):
        self.mac = mac
        self.ip = ip
        self.hostname = hostname
        self.device_type = device_type
        self.dns_queries = set()
        self.dns_query_count = 0
        self.total_traffic = 0
        self.avg_traffic = 0
        self.active_hours = set()
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.observation_count = 0
        self.offline_time = None
    
    def add_dns_query(self, domain: str):
        """添加DNS查询"""
        self.dns_queries.add(domain.lower())
        self.dns_query_count += 1
    
    def add_active_hour(self, hour: int):
        """添加活跃小时"""
        self.active_hours.add(hour)
    
    def update_traffic(self, bytes_count: int):
        """更新流量统计"""
        self.total_traffic += bytes_count
        self.observation_count += 1
        if self.observation_count > 0:
            self.avg_traffic = self.total_traffic / self.observation_count
    
    def update_time(self):
        """更新最后活跃时间"""
        self.last_seen = time.time()
    
    def to_dict(self) -> Dict:
        return {
            'mac': self.mac,
            'ip': self.ip,
            'hostname': self.hostname,
            'device_type': self.device_type,
            'dns_queries': list(self.dns_queries),
            'dns_query_count': self.dns_query_count,
            'total_traffic': self.total_traffic,
            'avg_traffic': self.avg_traffic,
            'active_hours': list(self.active_hours),
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'observation_count': self.observation_count,
            'offline_time': self.offline_time
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'DeviceProfile':
        profile = cls(
            data.get('mac', ''),
            data.get('ip', ''),
            data.get('hostname', ''),
            data.get('device_type', '')
        )
        profile.dns_queries = set(data.get('dns_queries', []))
        profile.dns_query_count = data.get('dns_query_count', 0)
        profile.total_traffic = data.get('total_traffic', 0)
        profile.avg_traffic = data.get('avg_traffic', 0)
        profile.active_hours = set(data.get('active_hours', []))
        profile.first_seen = data.get('first_seen', time.time())
        profile.last_seen = data.get('last_seen', time.time())
        profile.observation_count = data.get('observation_count', 0)
        profile.offline_time = data.get('offline_time')
        return profile


class DeviceCorrelator:
    """设备关联器"""
    
    def __init__(self, config, database):
        self.config = config
        self.database = database
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        self.enable_correlation = config.get_bool('ENABLE_DEVICE_CORRELATION', True)
        self.similarity_threshold = config.get_float('DEVICE_SIMILARITY_THRESHOLD', 0.7)
        self.merge_threshold = config.get_float('DEVICE_MERGE_THRESHOLD', 0.95)
        self.offline_time_window = config.get_int('OFFLINE_TIME_WINDOW', 3600)
        self.history_time_window = config.get_int('DEVICE_HISTORY_WINDOW', 86400)
        
        self._device_profiles = {}
        self._ip_to_macs = defaultdict(list)
        self._recent_offline_devices = {}
        self._historical_offline_devices = {}
    
    def initialize(self):
        """初始化设备关联器"""
        if not self.enable_correlation:
            self.logger.info("设备关联功能已禁用")
            return
        
        self.logger.info("初始化设备关联器")
        self.logger.info(f"相似度阈值: {self.similarity_threshold}")
        self.logger.info(f"离线时间窗口: {self.offline_time_window}秒")
        self.logger.info(f"历史设备窗口: {self.history_time_window}秒")
        
        self._load_profiles_from_database()
    
    def _load_profiles_from_database(self):
        """从数据库加载设备画像"""
        try:
            behaviors = self.database.load_device_behaviors()
            for mac, behavior_list in behaviors.items():
                if behavior_list:
                    latest = behavior_list[-1]
                    profile = DeviceProfile.from_dict(latest)
                    profile.offline_time = None
                    self._device_profiles[mac] = profile
                    self._ip_to_macs[profile.ip].append(mac)
            
            self.logger.info(f"从数据库加载了 {len(self._device_profiles)} 个设备画像")
        except Exception as e:
            self.logger.warning(f"加载设备画像失败: {e}")
    
    def update_device_behavior(self, device: Dict):
        """更新设备行为画像
        
        Args:
            device: 设备信息字典
        """
        if not self.enable_correlation:
            return
        
        mac = device.get('mac', '')
        ip = device.get('ip', '')
        hostname = device.get('hostname', '')
        device_type = device.get('device_type', '')
        
        if not mac or not ip:
            return
        
        if mac not in self._device_profiles:
            self._device_profiles[mac] = DeviceProfile(mac, ip, hostname, device_type)
        
        profile = self._device_profiles[mac]
        profile.ip = ip
        if hostname:
            profile.hostname = hostname
        if device_type:
            profile.device_type = device_type
        
        if 'dns_queries' in device:
            for domain in device['dns_queries']:
                profile.add_dns_query(domain)
        
        if 'recent_domains' in device:
            for domain in device['recent_domains']:
                profile.add_dns_query(domain)
        
        if 'bytes_total' in device:
            profile.update_traffic(device['bytes_total'])
        
        profile.update_time()
        
        self._ip_to_macs[ip].append(mac)
    
    def record_device_offline(self, device: Dict):
        """记录设备下线
        
        Args:
            device: 下线的设备信息
        """
        if not self.enable_correlation:
            return
        
        mac = device.get('mac', '')
        ip = device.get('ip', '')
        
        if not mac or not ip:
            return
        
        profile = None
        if mac in self._device_profiles:
            profile = self._device_profiles[mac]
            profile.offline_time = time.time()
        else:
            profile = DeviceProfile(
                mac=mac,
                ip=ip,
                hostname=device.get('hostname', ''),
                device_type=device.get('device_type', '')
            )
            profile.offline_time = time.time()
            self._device_profiles[mac] = profile
        
        self._recent_offline_devices[ip] = {
            'mac': mac,
            'profile': profile,
            'offline_time': time.time()
        }
        
        if ip not in self._historical_offline_devices:
            self._historical_offline_devices[ip] = []
        self._historical_offline_devices[ip].append({
            'mac': mac,
            'profile': profile,
            'offline_time': time.time()
        })
        
        self.logger.debug(f"记录设备下线: {mac} ({ip})")
    
    def check_device_reappeared(self, device: Dict) -> Optional[Dict]:
        """检查设备是否重新出现（MAC随机化场景）
        
        Args:
            device: 新上线的设备
            
        Returns:
            关联结果: {
                'is_same_device': bool,
                'original_mac': str,
                'similarity': float,
                'reason': str
            }
            如果不是关联场景，返回None
        """
        if not self.enable_correlation:
            return None
        
        current_mac = device.get('mac', '')
        current_ip = device.get('ip', '')
        
        if not current_mac or not current_ip:
            return None
        
        result = self._check_recent_offline(device, current_mac, current_ip)
        if result:
            return result
        
        result = self._check_historical_offline(device, current_mac, current_ip)
        if result:
            return result
        
        result = self._check_same_ip_different_mac(device, current_mac, current_ip)
        if result:
            return result
        
        result = self._check_profile_only(device, current_mac)
        if result:
            return result
        
        return None
    
    def _check_profile_only(self, device: Dict, current_mac: str) -> Optional[Dict]:
        """纯画像匹配（不看IP），用于IP变化但设备行为相似的情况"""
        if not self._device_profiles:
            return None
        
        best_match = None
        best_similarity = 0
        
        for original_mac, profile in self._device_profiles.items():
            if original_mac == current_mac:
                continue
            
            if profile.ip == device.get('ip'):
                continue
            
            similarity = self._calculate_similarity(device, profile)
            
            if similarity >= self.similarity_threshold and similarity > best_similarity:
                best_similarity = similarity
                best_match = {
                    'is_same_device': True,
                    'original_mac': original_mac,
                    'current_mac': current_mac,
                    'similarity': similarity,
                    'match_type': 'profile_only',
                    'reason': self._get_similarity_reason(device, profile, similarity)
                }
        
        return best_match
    
    def _check_recent_offline(self, device: Dict, current_mac: str, current_ip: str) -> Optional[Dict]:
        """检查最近下线的设备（短期窗口）"""
        if current_ip not in self._recent_offline_devices:
            return None
        
        offline_info = self._recent_offline_devices[current_ip]
        original_mac = offline_info['mac']
        original_profile = offline_info['profile']
        offline_time = offline_info['offline_time']
        
        if original_mac == current_mac:
            return None
        
        time_since_offline = time.time() - offline_time
        if time_since_offline > self.offline_time_window:
            del self._recent_offline_devices[current_ip]
            return None
        
        similarity = self._calculate_similarity(device, original_profile)
        
        if similarity >= self.similarity_threshold:
            result = {
                'is_same_device': True,
                'original_mac': original_mac,
                'current_mac': current_mac,
                'similarity': similarity,
                'match_type': 'recent_offline',
                'reason': self._get_similarity_reason(device, original_profile, similarity)
            }
            
            self.logger.info(
                f"检测到MAC随机化设备(近期下线): {current_mac}({current_ip}) "
                f"可能是 {original_mac} (相似度: {similarity:.1%})"
            )
            
            del self._recent_offline_devices[current_ip]
            
            return result
        
        return None
    
    def _check_historical_offline(self, device: Dict, current_mac: str, current_ip: str) -> Optional[Dict]:
        """检查历史下线的设备（长期窗口）"""
        if current_ip not in self._historical_offline_devices:
            return None
        
        candidates = self._historical_offline_devices[current_ip]
        current_time = time.time()
        
        valid_candidates = [
            c for c in candidates
            if current_time - c['offline_time'] <= self.history_time_window
        ]
        
        if not valid_candidates:
            del self._historical_offline_devices[current_ip]
            return None
        
        best_match = None
        best_similarity = 0
        
        for offline_info in valid_candidates:
            original_mac = offline_info['mac']
            original_profile = offline_info['profile']
            
            if original_mac == current_mac:
                continue
            
            similarity = self._calculate_similarity(device, original_profile)
            
            if similarity >= self.similarity_threshold and similarity > best_similarity:
                best_similarity = similarity
                best_match = {
                    'is_same_device': True,
                    'original_mac': original_mac,
                    'current_mac': current_mac,
                    'similarity': similarity,
                    'match_type': 'historical_offline',
                    'reason': self._get_similarity_reason(device, original_profile, similarity)
                }
        
        if best_match:
            self.logger.info(
                f"检测到MAC随机化设备(历史记录): {current_mac}({current_ip}) "
                f"可能是 {best_match['original_mac']} (相似度: {best_similarity:.1%})"
            )
        
        return best_match
    
    def _check_same_ip_different_mac(self, device: Dict, current_mac: str, current_ip: str) -> Optional[Dict]:
        """检查同IP不同MAC的设备（无需先下线）"""
        if current_ip not in self._ip_to_macs:
            return None
        
        previous_macs = self._ip_to_macs[current_ip]
        
        if len(previous_macs) <= 1 and current_mac in previous_macs:
            return None
        
        best_match = None
        best_similarity = 0
        
        for original_mac in previous_macs:
            if original_mac == current_mac:
                continue
            
            if original_mac not in self._device_profiles:
                continue
            
            original_profile = self._device_profiles[original_mac]
            
            similarity = self._calculate_similarity(device, original_profile)
            
            if similarity >= self.similarity_threshold and similarity > best_similarity:
                best_similarity = similarity
                best_match = {
                    'is_same_device': True,
                    'original_mac': original_mac,
                    'current_mac': current_mac,
                    'similarity': similarity,
                    'match_type': 'same_ip_different_mac',
                    'reason': self._get_similarity_reason(device, original_profile, similarity)
                }
        
        if best_match:
            self.logger.info(
                f"检测到MAC随机化设备(同IP匹配): {current_mac}({current_ip}) "
                f"可能是 {best_match['original_mac']} (相似度: {best_similarity:.1%})"
            )
        
        return best_match
    
    def _calculate_similarity(self, device: Dict, profile: DeviceProfile) -> float:
        """计算设备与历史画像的相似度
        
        Args:
            device: 当前设备
            profile: 历史画像
            
        Returns:
            相似度 (0-1)
        """
        weights = {
            'dns': 0.30,
            'traffic': 0.20,
            'hostname': 0.20,
            'device_type': 0.15,
            'active_hours': 0.15
        }
        
        total_score = 0.0
        
        dns_score = self._calculate_dns_similarity(device, profile)
        total_score += dns_score * weights['dns']
        
        traffic_score = self._calculate_traffic_similarity(device, profile)
        total_score += traffic_score * weights['traffic']
        
        hostname_score = self._calculate_hostname_similarity(device, profile)
        total_score += hostname_score * weights['hostname']
        
        device_type_score = self._calculate_device_type_similarity(device, profile)
        total_score += device_type_score * weights['device_type']
        
        active_hours_score = self._calculate_active_hours_similarity(device, profile)
        total_score += active_hours_score * weights['active_hours']
        
        return min(total_score, 1.0)
    
    def _calculate_device_type_similarity(self, device: Dict, profile: DeviceProfile) -> float:
        """计算设备类型相似度"""
        current_type = (device.get('device_type', '') or '').lower()
        old_type = (profile.device_type or '').lower()
        
        if not current_type and not old_type:
            return 0.5
        
        if not current_type or not old_type:
            return 0.0
        
        if current_type == old_type:
            return 1.0
        
        type_groups = {
            'phone': ['phone', 'mobile', 'iphone', 'android', 'smartphone'],
            'computer': ['computer', 'desktop', 'laptop', 'mac', 'pc', 'windows', 'linux'],
            'tablet': ['tablet', 'ipad', 'android tablet'],
            'tv': ['tv', 'television', 'smarttv', 'roku', 'firestick', 'chromecast'],
            'iot': ['iot', 'smart', 'sensor', 'camera', 'bulb', 'plug', 'speaker'],
            'nas': ['nas', 'storage', 'synology', 'qnap'],
            'router': ['router', 'gateway', 'ap'],
        }
        
        for group_name, keywords in type_groups.items():
            if any(kw in current_type for kw in keywords) and any(kw in old_type for kw in keywords):
                return 0.8
        
        return 0.0
    
    def _calculate_dns_similarity(self, device: Dict, profile: DeviceProfile) -> float:
        """计算DNS查询相似度"""
        device_dns = set()
        
        if 'dns_queries' in device:
            device_dns = set(device['dns_queries'])
        elif 'recent_domains' in device:
            device_dns = set(device['recent_domains'])
        
        if not device_dns and not profile.dns_queries:
            return 0.5
        
        if not device_dns or not profile.dns_queries:
            return 0.0
        
        intersection = len(device_dns & profile.dns_queries)
        union = len(device_dns | profile.dns_queries)
        
        jaccard = intersection / union if union > 0 else 0
        
        return jaccard
    
    def _calculate_traffic_similarity(self, device: Dict, profile: DeviceProfile) -> float:
        """计算流量模式相似度"""
        device_traffic = device.get('bytes_total', 0)
        
        if device_traffic == 0 and profile.avg_traffic == 0:
            return 0.5
        
        if device_traffic == 0 or profile.avg_traffic == 0:
            return 0.0
        
        ratio = min(device_traffic, profile.avg_traffic) / max(device_traffic, profile.avg_traffic)
        
        return ratio
    
    def _calculate_hostname_similarity(self, device: Dict, profile: DeviceProfile) -> float:
        """计算主机名相似度"""
        current_hostname = (device.get('hostname', '') or '').lower()
        old_hostname = (profile.hostname or '').lower()
        
        if not current_hostname and not old_hostname:
            return 0.5
        
        if not current_hostname or not old_hostname:
            return 0.0
        
        if current_hostname == old_hostname:
            return 1.0
        
        current_parts = set(current_hostname.replace('-', ' ').replace('_', ' ').split())
        old_parts = set(old_hostname.replace('-', ' ').replace('_', ' ').split())
        
        if not current_parts or not old_parts:
            return 0.0
        
        intersection = len(current_parts & old_parts)
        union = len(current_parts | old_parts)
        
        return intersection / union if union > 0 else 0.0
    
    def _calculate_active_hours_similarity(self, device: Dict, profile: DeviceProfile) -> float:
        """计算活跃时间相似度"""
        current_hour = datetime.now().hour
        
        if not profile.active_hours:
            return 0.5
        
        if current_hour in profile.active_hours:
            return 1.0
        
        for hour in profile.active_hours:
            if abs(current_hour - hour) <= 2:
                return 0.6
        
        return 0.0
    
    def _get_similarity_reason(self, device: Dict, profile: DeviceProfile, similarity: float) -> str:
        """获取相似度原因"""
        reasons = []
        
        device_dns = set(device.get('dns_queries', [])) if 'dns_queries' in device else set()
        if device_dns & profile.dns_queries:
            common_domains = list(device_dns & profile.dns_queries)[:3]
            reasons.append(f"共同DNS域名: {', '.join(common_domains)}")
        
        device_hostname = device.get('hostname', '')
        if device_hostname and profile.hostname:
            if device_hostname.lower() == profile.hostname.lower():
                reasons.append(f"相同主机名: {device_hostname}")
        
        current_hour = datetime.now().hour
        if current_hour in profile.active_hours:
            reasons.append(f"活跃时间匹配")
        
        if not reasons:
            reasons.append(f"综合行为相似度高 ({similarity:.0%})")
        
        return "; ".join(reasons)
    
    def get_potential_random_mac_devices(self) -> List[Dict]:
        """获取可能是MAC随机化的设备列表
        
        Returns:
            潜在的MAC随机化设备列表
        """
        results = []
        
        current_time = time.time()
        
        for ip, offline_info in self._recent_offline_devices.items():
            offline_time = offline_info['offline_time']
            time_since_offline = current_time - offline_time
            
            if time_since_offline < self.offline_time_window:
                results.append({
                    'ip': ip,
                    'original_mac': offline_info['mac'],
                    'offline_duration': int(time_since_offline),
                    'profile': offline_info['profile'].to_dict()
                })
        
        return results
    
    def clear_old_offline_records(self):
        """清理过期的离线记录"""
        current_time = time.time()
        expired_ips = []
        
        for ip, info in self._recent_offline_devices.items():
            if current_time - info['offline_time'] > self.offline_time_window:
                expired_ips.append(ip)
        
        for ip in expired_ips:
            del self._recent_offline_devices[ip]
        
        if expired_ips:
            self.logger.debug(f"清理了 {len(expired_ips)} 条过期离线记录")
    
    def merge_device_profiles(self, original_mac: str, new_mac: str):
        """合并设备画像
        
        当确定两个MAC是同一设备时，合并画像
        
        Args:
            original_mac: 原MAC地址
            new_mac: 新MAC地址
        """
        if original_mac not in self._device_profiles:
            self.logger.warning(f"原设备画像不存在: {original_mac}")
            return
        
        original_profile = self._device_profiles[original_mac]
        
        if new_mac in self._device_profiles:
            new_profile = self._device_profiles[new_mac]
            
            original_profile.dns_queries |= new_profile.dns_queries
            original_profile.dns_query_count += new_profile.dns_query_count
            original_profile.total_traffic += new_profile.total_traffic
            original_profile.active_hours |= new_profile.active_hours
            original_profile.observation_count += new_profile.observation_count
        
        self._device_profiles[new_mac] = original_profile
        
        if new_mac != original_mac and original_mac in self._device_profiles:
            del self._device_profiles[original_mac]
        
        original_ip = original_profile.ip
        
        if new_mac not in self._ip_to_macs[original_ip]:
            self._ip_to_macs[original_ip].append(new_mac)
        
        self.logger.info(f"已合并设备画像: {original_mac} -> {new_mac}")
