#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
设备工具模块
"""

import logging
from typing import Dict, Optional, Tuple

logger = logging.getLogger('LanSecurityMonitor')


class DeviceUtils:
    """设备工具类"""
    
    # 厂商OUI数据库（前3字节）
    VENDOR_OUI = {
        # 智能家居厂商
        '28:6D:97': '小米',
        '5C:8D:4E': '涂鸦智能',
        '48:E1:E9': '华为',
        '7C:5C:F8': '萤石',
        'AC:CF:23': '海康威视',
        'A4:C4:94': '绿米',
        '34:CE:00': '乐鑫科技（ESP芯片）',
        
        # NAS厂商
        '00:11:32': '群晖',
        '00:04:A2': '群晖',
        # '00:E0:4C': '群晖',  # 移除，这个是 Realtek
        '24:69:8E': '威联通',
        '24:5E:BE': '威联通',
        '00:08:9B': '威联通',
        '00:0E:A6': '威联通',
        '00:13:49': '威联通',
        '00:1D:09': '威联通',
        '00:1E:06': '铁威马',
        '00:15:5D': 'Asustor',
        '00:1B:21': 'Buffalo',
        '00:1B:63': 'Thecus',
        
        # Apple设备
        '00:0C:42': 'Apple',
        '00:25:00': 'Apple',
        '3C:07:54': 'Apple',
        '58:11:22': 'Apple',
        'AC:DE:48': 'Apple',
        
        # PC/主板厂商
        '00:E0:4C': 'Realtek',
        
        # 游戏主机
        '00:09:BF': 'Nintendo',
        '00:1A:E9': 'Nintendo',
        '00:1F:5B': 'Xbox',
        '00:25:AE': 'Xbox',
        '00:22:48': 'PlayStation',
        '00:D8:61': 'PlayStation',
        
        # 虚拟化平台
        '00:0C:29': 'VMware',
        '00:50:56': 'VMware',
        '00:1C:42': 'Parallels',
        
        # 其他
        '00:0D:3A': 'HP',
        '00:1B:44': 'Intel',
    }
    
    # 设备类型映射
    DEVICE_TYPES = {
        # 智能家居设备
        'xiaomi': 'smart_home',
        'diy': 'smart_home',
        'huawei': 'smart_home',
        'ezviz': 'smart_home',
        'hikvision': 'smart_home',
        'aqara': 'smart_home',
        'espressif': 'smart_home',
        
        # NAS设备
        'synology': 'nas',
        '群晖': 'nas',
        'qnap': 'nas',
        '威联通': 'nas',
        'terramaster': 'nas',
        '铁威马': 'nas',
        'netgear': 'nas',
        'asustor': 'nas',
        'buffalo': 'nas',
        'thecus': 'nas',
        
        # 其他设备类型
        'apple': 'personal_device',
        'intel': 'computer',
        'hp': 'computer',
        'vmware': 'virtual_machine',
        'hyper-v': 'virtual_machine',
        'parallels': 'virtual_machine',
        'nintendo': 'game_console',
        'xbox': 'game_console',
        'playstation': 'game_console',
    }
    
    @classmethod
    def get_vendor_from_mac(cls, mac: str) -> Optional[str]:
        """从MAC地址获取厂商
        
        Args:
            mac: MAC地址
            
        Returns:
            厂商名称或None
        """
        if not mac:
            return None
        
        try:
            # 提取前3字节（OUI）
            oui = mac.upper().replace(':', '')[:6]
            # 格式化为XX:XX:XX
            oui_formatted = ':'.join([oui[i:i+2] for i in range(0, 6, 2)])
            
            return cls.VENDOR_OUI.get(oui_formatted)
        except Exception as e:
            logger.error(f"解析MAC地址失败: {str(e)}")
            return None
    
    @classmethod
    def get_device_type(cls, vendor: str, hostname: str) -> str:
        """获取设备类型（多特征融合识别）
        
        优先级：
        1. 用户手动标记的类型（需传入 database）
        2. 主机名特征
        3. 厂商特征
        
        Args:
            vendor: 厂商名称
            hostname: 主机名
            
        Returns:
            设备类型
        """
        if not vendor:
            return 'unknown'
        
        vendor_lower = vendor.lower()
        
        # 从主机名优先判断
        if hostname:
            hostname_lower = hostname.lower()
            if any(key in hostname_lower for key in ['nas', 'synology', 'qnap', 'terramaster']):
                return 'nas'
            elif any(key in hostname_lower for key in ['smart', 'home', 'iot', 'zigbee', 'zwave']):
                return 'smart_home'
            elif any(key in hostname_lower for key in ['apple', 'iphone', 'ipad', 'macbook', 'mac-mini', 'macmini', 'imac']):
                return 'personal_device'
            elif any(key in hostname_lower for key in ['pc', 'desktop', 'laptop', 'computer', 'thinkpad', ' XPS ', 'spectre', 'envy', 'pavilion', 'legion', 'rog', 'predator', 'razer']):
                return 'computer'
            elif any(key in hostname_lower for key in ['tv', 'display', 'screen', 'smarttv', 'smart-tv']):
                return 'tv'
            elif any(key in hostname_lower for key in ['phone', 'mobile', 'android', 'iphone', 'huawei-', 'xiaomi-', 'oppo-', 'vivo-', 'oneplus']):
                return 'mobile'
            elif any(key in hostname_lower for key in ['printer', 'print']):
                return 'printer'
            elif any(key in hostname_lower for key in ['camera', 'cam', 'ipcam', 'nvr']):
                return 'camera'
            elif any(key in hostname_lower for key in ['router', 'gateway', 'ax', 'rt', 'mesh']):
                return 'router'
        
        # 从厂商映射
        for key, device_type in cls.DEVICE_TYPES.items():
            if key in vendor_lower:
                return device_type
        
        # 特殊处理扩展坞/网卡
        if any(key in vendor_lower for key in ['realtek', 'broadcom', 'intel', 'atheros']):
            return 'computer'
        
        return 'unknown'
    
    @classmethod
    def get_device_type_with_database(cls, vendor: str, hostname: str, database=None, mac: str = None) -> str:
        """获取设备类型（支持数据库用户标记）
        
        Args:
            vendor: 厂商名称
            hostname: 主机名
            database: 数据库实例
            mac: MAC地址
            
        Returns:
            设备类型
        """
        # 1. 如果有数据库，优先查询用户标记的类型
        if database and mac:
            try:
                device = database.load_device_by_mac(mac)
                if device and device.get('device_type'):
                    user_type = device.get('device_type')
                    if user_type and user_type != 'unknown':
                        logger.info(f"使用用户标记的设备类型: {mac} -> {user_type}")
                        return user_type
            except Exception as e:
                logger.debug(f"查询用户设备类型失败: {e}")
        
        # 2. 使用多特征融合识别
        return cls.get_device_type(vendor, hostname)
    
    @classmethod
    def get_device_category(cls, device_type: str) -> str:
        """获取设备分类
        
        Args:
            device_type: 设备类型
            
        Returns:
            设备分类
        """
        categories = {
            'nas': 'core',  # 核心设备
            'smart_home': 'iot',  # 物联网设备
            'computer': 'core',  # 核心设备
            'personal_device': 'core',  # 核心设备
            'mobile': 'core',  # 核心设备
            'tv': 'entertainment',  # 娱乐设备
            'camera': 'security',  # 安防设备
            'printer': 'peripheral',  # 外设
            'game_console': 'entertainment',  # 娱乐设备
            'virtual_machine': 'virtual',  # 虚拟设备
            'unknown': 'unknown'  # 未知设备
        }
        
        return categories.get(device_type, 'unknown')
    
    @classmethod
    def analyze_device(cls, device: Dict) -> Dict:
        """分析设备信息
        
        Args:
            device: 设备信息
            
        Returns:
            增强后的设备信息
        """
        mac = device.get('mac')
        hostname = device.get('hostname', '')
        
        # 获取厂商
        vendor = cls.get_vendor_from_mac(mac)
        device['vendor'] = vendor or device.get('vendor', '')
        
        # 获取设备类型
        device_type = cls.get_device_type(vendor, hostname)
        device['device_type'] = device_type
        
        # 获取设备分类
        category = cls.get_device_category(device_type)
        device['category'] = category
        
        # 设置默认风险等级
        device['risk_level'] = cls._get_default_risk_level(category)
        
        return device
    
    @classmethod
    def _get_default_risk_level(cls, category: str) -> str:
        """获取默认风险等级
        
        Args:
            category: 设备分类
            
        Returns:
            风险等级
        """
        risk_levels = {
            'core': 'low',  # 核心设备风险低
            'iot': 'medium',  # 物联网设备风险中等
            'entertainment': 'low',  # 娱乐设备风险低
            'security': 'medium',  # 安防设备风险中等
            'peripheral': 'low',  # 外设风险低
            'virtual': 'medium',  # 虚拟设备风险中等
            'unknown': 'high'  # 未知设备风险高
        }
        
        return risk_levels.get(category, 'medium')