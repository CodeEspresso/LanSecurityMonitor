#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNS监控模块
从AdGuard Home获取DNS查询日志并进行威胁检测
"""

import os
import logging
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict

import requests

logger = logging.getLogger('LanSecurityMonitor')


class DNSQuery:
    """DNS查询记录"""
    
    def __init__(self, data: Dict):
        self.domain = data.get('name', '')
        self.qtype = data.get('type', 'A')
        self.client_ip = data.get('client', '')
        self.client_name = data.get('client_name', '')
        self.timestamp = data.get('time', '')
        self.response_status = data.get('response', {}).get('status', '')
        self.ip = data.get('response', {}).get('answer', [{}])[0].get('value', '')
    
    def to_dict(self) -> Dict:
        return {
            'domain': self.domain,
            'qtype': self.qtype,
            'client_ip': self.client_ip,
            'client_name': self.client_name,
            'timestamp': self.timestamp,
            'response_status': self.response_status,
            'ip': self.ip
        }


class AdGuardClient:
    """AdGuard Home API客户端"""
    
    def __init__(self, config, secure_config):
        self.config = config
        self.secure_config = secure_config
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        self.base_url = os.environ.get('ADGUARD_URL', '')
        self.username = os.environ.get('ADGUARD_USERNAME', 'admin')
        self.password = os.environ.get('ADGUARD_PASSWORD', '')
        
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/json'
        })
        
        self._authenticated = False
    
    def _authenticate(self) -> bool:
        """AdGuard认证"""
        if not self.base_url or not self.password:
            return False
        
        self.logger.info(f"尝试登录AdGuard: {self.base_url}, 用户名: {self.username}")
        
        try:
            response = self.session.post(
                f"{self.base_url}/control/login",
                json={'name': self.username, 'password': self.password},
                timeout=10,
                verify=False
            )
            
            self.logger.info(f"AdGuard登录响应: HTTP {response.status_code}")
            
            if response.status_code == 200:
                self._authenticated = True
                return True
            else:
                self.logger.warning(f"AdGuard认证失败: HTTP {response.status_code}, 响应: {response.text[:200]}")
                return False
        except Exception as e:
            self.logger.warning(f"AdGuard认证异常: {e}")
            return False
    
    def _check_connection(self) -> bool:
        """检查AdGuard连接"""
        if not self.base_url:
            self.logger.warning("AdGuard URL未配置")
            return False
        
        try:
            response = self.session.get(
                f"{self.base_url}/control/status",
                timeout=10,
                verify=False
            )
            
            if response.status_code == 200:
                return True
            elif response.status_code in [401, 403]:
                self.logger.info("AdGuard需要认证，尝试登录...")
                return self._authenticate()
            else:
                self.logger.warning(f"AdGuard连接失败: HTTP {response.status_code}")
                return False
        except Exception as e:
            self.logger.warning(f"AdGuard连接异常: {e}")
            return False
    
    def get_dns_log(self, limit: int = 1000) -> List[Dict]:
        """获取DNS查询日志"""
        if not self._check_connection():
            self.logger.warning("AdGuard Home未连接")
            return []
        
        try:
            response = self.session.get(
                f"{self.base_url}/control/querylog",
                params={'limit': limit},
                timeout=30,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                self.logger.warning(f"获取DNS日志失败: {response.status_code}")
                return []
                
        except Exception as e:
            self.logger.error(f"获取DNS日志出错: {e}")
            return []
    
    def get_query_stats(self) -> Dict:
        """获取DNS查询统计"""
        if not self._check_connection():
            return {}
        
        try:
            response = self.session.get(
                f"{self.base_url}/control/stats",
                timeout=10,
                verify=False
            )
            
            if response.status_code == 200:
                return response.json()
            return {}
        except Exception as e:
            self.logger.debug(f"获取DNS统计失败: {e}")
            return {}


class DGADetector:
    """DGA（域名生成算法）检测器 - 使用IsolationForest+N-gram"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        self.enabled = config.get_bool('ENABLE_DGA_DETECTION', True)
        self.method = config.get('DGA_DETECTION_METHOD', 'pretrained')
        self.threshold = config.get_float('DGA_THRESHOLD', 0.7)
        self.model_dir = config.get('ML_MODEL_DIR', 'data/ml_models')
        
        self._model = None
        self._vectorizer = None
        self._scaler = None
        self._normal_domains = []
        
        self._initialize()
    
    def _initialize(self):
        """初始化检测器"""
        if not self.enabled:
            self.logger.info("DGA检测已禁用")
            return
        
        self.logger.info(f"初始化DGA检测器，方法: {self.method}")
        
        if self.method in ('pretrained', 'both'):
            self._load_pretrained_model()
        
        if self._model is None:
            self.logger.info("将使用规则引擎作为后备检测")
    
    def _load_pretrained_model(self):
        """加载预训练IsolationForest模型"""
        try:
            import joblib
            
            model_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                self.model_dir
            )
            os.makedirs(model_dir, exist_ok=True)
            
            model_path = os.path.join(model_dir, 'dns_model.pkl')
            
            if os.path.exists(model_path):
                self._model = joblib.load(model_path)
                self.logger.info("已加载IsolationForest DGA检测模型")
            else:
                self.logger.info("预训练模型不存在，检查是否需要训练...")
                self._try_train_model()
                
        except ImportError:
            self.logger.warning("joblib不可用，将使用规则引擎检测")
            self._model = None
    
    def _try_train_model(self):
        """尝试训练模型（使用内置正常域名）"""
        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest
            from sklearn.feature_extraction.text import CountVectorizer
            from sklearn.preprocessing import StandardScaler
            import joblib
            
            self.logger.info("初始化训练正常域名库...")
            
            normal_domains = self._get_normal_domains()
            if len(normal_domains) < 10:
                self.logger.warning("正常域名数据不足，使用规则引擎")
                return
            
            self.logger.info(f"使用 {len(normal_domains)} 个正常域名训练模型...")
            
            self._vectorizer = CountVectorizer(
                analyzer='char',
                ngram_range=(2, 4),
                max_features=500
            )
            
            # 先 fit vectorizer
            self._vectorizer.fit(normal_domains)
            
            X_stats, X_ngrams = self._extract_features(normal_domains)
            X_combined = np.hstack([X_stats, X_ngrams])
            
            self._scaler = StandardScaler()
            X_scaled = self._scaler.fit_transform(X_combined)
            
            self._model = IsolationForest(
                contamination=0.01,
                n_estimators=100,
                max_samples=256,
                random_state=42,
                n_jobs=-1
            )
            
            self._model.fit(X_scaled)
            
            model_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                self.model_dir
            )
            os.makedirs(model_dir, exist_ok=True)
            
            model_path = os.path.join(model_dir, 'dns_model.pkl')
            joblib.dump(self._model, model_path)
            self.logger.info(f"模型已保存: {model_path}")
            
        except Exception as e:
            self.logger.warning(f"模型训练失败: {e}，使用规则引擎")
            self._model = None
    
    def _get_normal_domains(self):
        """获取正常域名列表"""
        return [
            "baidu.com", "taobao.com", "jd.com", "qq.com", "weibo.com",
            "bilibili.com", "zhihu.com", "163.com", "sina.com", "sohu.com",
            "aliyun.com", "icloud.com", "google.com", "github.com",
            "microsoft.com", "apple.com", "amazon.com", "twitter.com",
            "mi.com", "xiaomi.com", "huawei.com", "djicdn.com",
            "hikvision.com", "ezviz7.com", "philips.com", "yeelight.com",
            "alicdn.com", "aliyuncs.com", "qcloud.com", "bdstatic.com",
            "wechat.com", "tencent-cloud.net", "cloudflare.com",
            "cdn.jsdelivr.net", "fonts.googleapis.com", "ajax.googleapis.com"
        ]
    
    def _extract_features(self, domains):
        """提取特征（统计+N-gram）"""
        import numpy as np
        
        stats = []
        for domain in domains:
            domain = domain.lower()
            parts = domain.split('.')
            
            stat = [
                len(domain),
                len(parts),
                np.mean([len(p) for p in parts]) if parts else 0,
                sum(c.isdigit() for c in domain),
                sum(c == '-' for c in domain),
                self._calculate_entropy(domain)
            ]
            stats.append(stat)
        
        X_stats = np.array(stats)
        
        if self._vectorizer:
            X_ngrams = self._vectorizer.transform(domains).toarray()
        else:
            X_ngrams = np.zeros((len(domains), 1))
        
        return X_stats, X_ngrams
    
    def _calculate_entropy(self, s):
        """计算字符熵"""
        if not s:
            return 0.0
        from collections import Counter
        counter = Counter(s)
        length = len(s)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * np.log2(p)
        return entropy
    
    def _ml_detection(self, domain):
        """ML模型检测"""
        import numpy as np
        
        if self._model is None:
            return self._rule_based_detection(domain)
        
        try:
            domain = domain.lower()
            
            if self._vectorizer is None:
                from sklearn.feature_extraction.text import CountVectorizer
                self._vectorizer = CountVectorizer(
                    analyzer='char',
                    ngram_range=(2, 4),
                    max_features=500
                )
                normal = self._get_normal_domains()
                self._vectorizer.fit(normal)
            
            stats = np.array([[
                len(domain),
                len(domain.split('.')),
                np.mean([len(p) for p in domain.split('.')]) if '.' in domain else len(domain),
                sum(c.isdigit() for c in domain),
                sum(c == '-' for c in domain),
                self._calculate_entropy(domain)
            ]])
            
            ngrams = self._vectorizer.transform([domain]).toarray()
            X = np.hstack([stats, ngrams])
            
            if self._scaler:
                X = self._scaler.transform(X)
            
            score = self._model.decision_function(X)[0]
            is_anomaly = self._model.predict(X)[0] == -1
            
            confidence = abs(score)
            
            if is_anomaly and confidence > 0.3:
                return confidence
            return 0.0
            
        except Exception as e:
            self.logger.debug(f"ML检测失败: {e}")
            return self._rule_based_detection(domain)
    
    def _load_ml_model(self):
        """加载ML模型"""
        pass
    
    def _extract_domain_features(self, domain: str) -> Dict:
        """提取域名特征"""
        features = {}
        
        domain = domain.lower().rstrip('.')
        
        features['length'] = len(domain)
        features['num_dots'] = domain.count('.')
        features['num_hyphens'] = domain.count('-')
        features['num_digits'] = sum(c.isdigit() for c in domain)
        features['digit_ratio'] = features['num_digits'] / max(len(domain), 1)
        features['has_digits'] = 1 if features['num_digits'] > 0 else 0
        features['has_hyphen'] = 1 if features['num_hyphens'] > 0 else 0
        
        parts = domain.split('.')
        features['num_parts'] = len(parts)
        
        if parts:
            main_part = parts[-2] if len(parts) > 1 else parts[0]
            features['main_part_length'] = len(main_part)
            features['main_part_entropy'] = self._calculate_entropy(main_part)
            features['has_random_pattern'] = self._detect_random_pattern(main_part)
        
        features['tld'] = parts[-1] if parts else ''
        features['is_common_tld'] = self._is_common_tld(features['tld'])
        
        return features
    
    def _calculate_entropy(self, s: str) -> float:
        """计算字符熵"""
        from collections import Counter
        import math
        
        if not s:
            return 0.0
        
        counter = Counter(s)
        length = len(s)
        
        entropy = 0.0
        for count in counter.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _detect_random_pattern(self, s: str) -> int:
        """检测随机模式（DGA特征）"""
        if len(s) < 6:
            return 0
        
        consonant_clusters = ['bl', 'br', 'ch', 'cl', 'cr', 'dr', 'fl', 'fr', 'gl', 
                            'gr', 'pl', 'pr', 'sc', 'sh', 'sk', 'sl', 'sm', 'sn', 
                            'sp', 'st', 'sw', 'tr', 'tw', 'th', 'qu']
        
        s_lower = s.lower()
        cluster_count = sum(1 for c in consonant_clusters if c in s_lower)
        
        if cluster_count >= 2:
            return 1
        
        if len(s) >= 8:
            unique_ratio = len(set(s)) / len(s)
            if unique_ratio > 0.8:
                return 1
        
        return 0
    
    def _is_common_tld(self, tld: str) -> int:
        """检查是否为常见TLD"""
        common_tlds = {
            'com', 'net', 'org', 'edu', 'gov', 'co', 'io', 'cn', 'com.cn',
            'net.cn', 'org.cn', 'gov.cn', 'info', 'biz', 'me', 'cc', 'tv',
            'xyz', 'top', 'wang', 'site', 'club', 'online'
        }
        return 1 if tld.lower() in common_tlds else 0
    
    def _rule_based_detection(self, domain: str) -> float:
        """基于规则的DGA检测"""
        features = self._extract_domain_features(domain)
        
        score = 0.0
        
        if features['length'] > 20:
            score += 0.3
        if features['length'] > 30:
            score += 0.3
        
        if features['digit_ratio'] > 0.5:
            score += 0.4
        elif features['digit_ratio'] > 0.3:
            score += 0.2
        
        if features['has_random_pattern'] == 1:
            score += 0.5
        
        if features['main_part_entropy'] > 3.5:
            score += 0.3
        elif features['main_part_entropy'] > 3.0:
            score += 0.15
        
        if features['is_common_tld'] == 0 and features['length'] > 15:
            score += 0.2
        
        if features['num_parts'] > 4:
            score += 0.2
        
        return min(score, 1.0)
    
    def _ml_detection(self, domain: str) -> float:
        """ML模型检测"""
        if self._model is None:
            return self._rule_based_detection(domain)
        
        try:
            import numpy as np
            
            features = self._extract_domain_features(domain)
            
            feature_vector = np.array([
                features['length'],
                features['num_dots'],
                features['num_hyphens'],
                features['digit_ratio'],
                features['has_digits'],
                features['has_hyphen'],
                features['num_parts'],
                features['main_part_length'],
                features['main_part_entropy'],
                features['has_random_pattern'],
                features['is_common_tld']
            ]).reshape(1, -1)
            
            prob = self._model.predict_proba(feature_vector)[0][1]
            return float(prob)
            
        except Exception as e:
            self.logger.debug(f"ML检测失败: {e}")
            return self._rule_based_detection(domain)
    
    def detect(self, domain: str) -> Dict:
        """检测域名是否为DGA生成"""
        if not self.enabled or not domain:
            return {'is_dga': False, 'confidence': 0.0, 'method': 'disabled'}
        
        if self.method == 'pretrained':
            confidence = self._ml_detection(domain)
        elif self.method == 'ml':
            confidence = self._ml_detection(domain)
        else:
            confidence = self._rule_based_detection(domain)
        
        is_dga = confidence >= self.threshold
        
        return {
            'is_dga': is_dga,
            'confidence': confidence,
            'method': self.method,
            'threshold': self.threshold
        }


class MaliciousDomainMatcher:
    """恶意域名匹配器"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        self.enabled = config.get_bool('ENABLE_MALICIOUS_DOMAIN_MATCH', True)
        self._domains = set()
        self._load_domain_lists()
    
    def _load_domain_lists(self):
        """加载恶意域名列表"""
        if not self.enabled:
            return
        
        self.logger.info("加载恶意域名列表...")
        
        common_malicious = [
            'malware.test',
            'phishing.test',
            'ransomware.test',
            'c2.test',
            'botnet.test',
        ]
        
        self._domains = set(common_malicious)
        self.logger.info(f"已加载 {len(self._domains)} 个恶意域名规则")
    
    def check(self, domain: str) -> bool:
        """检查域名是否为恶意"""
        if not self.enabled or not domain:
            return False
        
        domain = domain.lower().rstrip('.')
        
        if domain in self._domains:
            return True
        
        for malicious in self._domains:
            if malicious in domain:
                return True
        
        return False


class DNSTunnelDetector:
    """DNS隧道检测器"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        self.enabled = config.get_bool('ENABLE_DNS_TUNNEL_DETECTION', False)
        self.qps_threshold = config.get_int('DNS_TUNNEL_QPS_THRESHOLD', 50)
        
        self._query_history = defaultdict(list)
    
    def _clean_history(self):
        """清理历史记录（保留1分钟内的数据）"""
        cutoff = time.time() - 60
        for client_ip in list(self._query_history.keys()):
            self._query_history[client_ip] = [
                t for t in self._query_history[client_ip] if t > cutoff
            ]
            if not self._query_history[client_ip]:
                del self._query_history[client_ip]
    
    def check_client(self, client_ip: str) -> Dict:
        """检测客户端是否存在DNS隧道特征"""
        if not self.enabled:
            return {'is_tunnel': False, 'qps': 0}
        
        self._clean_history()
        
        now = time.time()
        self._query_history[client_ip].append(now)
        
        recent_queries = [
            t for t in self._query_history[client_ip] 
            if now - t <= 10
        ]
        
        qps = len(recent_queries) / 10.0
        
        is_tunnel = qps > self.qps_threshold
        
        return {
            'is_tunnel': is_tunnel,
            'qps': qps,
            'threshold': self.qps_threshold
        }


class DNSMonitor:
    """DNS监控器主类"""
    
    def __init__(self, config, secure_config):
        self.config = config
        self.secure_config = secure_config
        self.logger = logging.getLogger('LanSecurityMonitor')
        
        self.enabled = config.get_bool('ENABLE_DNS_MONITOR', False)
        self.interval = config.get_int('DNS_MONITOR_INTERVAL', 60)
        self.alert_threshold = config.get('DNS_ALERT_THRESHOLD', 'medium')
        
        self._client = None
        self._dga_detector = None
        self._malicious_matcher = None
        self._tunnel_detector = None
        
        self._last_check_time = 0
        self._known_threats = {}
    
    def initialize(self):
        """初始化DNS监控器"""
        if not self.enabled:
            self.logger.info("DNS监控已禁用")
            return
        
        self.logger.info("初始化DNS监控器...")
        
        self._client = AdGuardClient(self.config, self.secure_config)
        self._dga_detector = DGADetector(self.config)
        self._malicious_matcher = MaliciousDomainMatcher(self.config)
        self._tunnel_detector = DNSTunnelDetector(self.config)
        
        if self._client._check_connection():
            self.logger.info("✅ 已连接到AdGuard Home")
        else:
            self.logger.warning("⚠️  无法连接到AdGuard Home，请检查配置")
    
    def check(self) -> List[Dict]:
        """执行DNS检查"""
        if not self.enabled:
            return []
        
        now = time.time()
        if now - self._last_check_time < self.interval:
            return []
        
        self._last_check_time = now
        
        threats = []
        
        dns_logs = self._client.get_dns_log(limit=500)
        
        if not dns_logs:
            return []
        
        seen_domains = set()
        
        for log_entry in dns_logs:
            query = DNSQuery(log_entry)
            
            if not query.domain or query.domain in seen_domains:
                continue
            
            seen_domains.add(query.domain)
            
            threat = self._analyze_query(query)
            if threat:
                threats.append(threat)
        
        return threats
    
    def _analyze_query(self, query: DNSQuery) -> Optional[Dict]:
        """分析单个DNS查询"""
        threat = None
        
        device = {
            'ip': query.client_ip,
            'hostname': query.client_name or query.client_ip,
            'mac': ''
        }
        
        if self._malicious_matcher.check(query.domain):
            threat = {
                'type': 'malicious_domain',
                'domain': query.domain,
                'client_ip': query.client_ip,
                'client_name': query.client_name,
                'qtype': query.qtype,
                'severity': 'high',
                'description': f"恶意域名: {query.domain}",
                'timestamp': query.timestamp,
                'device': device
            }
        
        dga_result = self._dga_detector.detect(query.domain)
        if dga_result['is_dga']:
            severity = 'high' if dga_result['confidence'] > 0.9 else 'medium'
            threat = {
                'type': 'dga_domain',
                'domain': query.domain,
                'client_ip': query.client_ip,
                'client_name': query.client_name,
                'qtype': query.qtype,
                'severity': severity,
                'confidence': dga_result['confidence'],
                'method': dga_result['method'],
                'description': f"DGA生成域名 (置信度: {dga_result['confidence']:.1%})",
                'timestamp': query.timestamp,
                'device': device
            }
        
        tunnel_result = self._tunnel_detector.check_client(query.client_ip)
        if tunnel_result['is_tunnel']:
            threat = {
                'type': 'dns_tunnel',
                'domain': query.domain,
                'client_ip': query.client_ip,
                'client_name': query.client_name,
                'qtype': query.qtype,
                'severity': 'critical',
                'qps': tunnel_result['qps'],
                'description': f"疑似DNS隧道 (QPS: {tunnel_result['qps']:.1f})",
                'timestamp': query.timestamp,
                'device': device
            }
        
        return threat
    
    def get_stats(self) -> Dict:
        """获取DNS统计信息"""
        if not self._client:
            return {}
        
        stats = self._client.get_query_stats()
        return {
            'dns_queries_today': stats.get('dns_queries', 0),
            'blocked_today': stats.get('blocked_filtering', 0),
            'ad_blocked': stats.get('blocked_safe_browsing', 0),
        }
