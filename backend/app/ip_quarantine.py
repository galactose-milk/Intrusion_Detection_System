# backend/app/ip_quarantine.py
"""
IP-Based Attack Detection and Quarantine System

Detects and blocks attacking IPs based on:
- Request rate (DoS/DDoS detection)
- Endpoint scanning patterns (recon detection)
- Failed request patterns (brute force detection)
- Suspicious request patterns

This system works alongside process_quarantine.py to provide
complete protection against both network attacks and local threats.
"""

import asyncio
import time
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Set, Callable
from threading import Lock
import ipaddress

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AttackType(Enum):
    """Types of network-based attacks"""
    DOS_FLOOD = "dos_flood"              # High request rate from single IP
    DDOS_FLOOD = "ddos_flood"            # Coordinated attack from multiple IPs
    ENDPOINT_SCAN = "endpoint_scan"      # Probing multiple endpoints
    BRUTE_FORCE = "brute_force"          # Repeated failed auth attempts
    RATE_LIMIT_EXCEEDED = "rate_limit"   # General rate limit violation
    SUSPICIOUS_PATTERN = "suspicious"     # Unusual request patterns


class BlockAction(Enum):
    """Actions to take on detected attacks"""
    WARN = "warn"           # Log warning, don't block
    THROTTLE = "throttle"   # Slow down requests
    TEMP_BLOCK = "temp_block"  # Temporary block (5-15 min)
    BLOCK = "block"         # Block until manually unblocked
    PERMANENT = "permanent"  # Permanent block (persisted)


@dataclass
class IPRequestStats:
    """Statistics for a single IP address"""
    ip: str
    first_seen: datetime
    last_seen: datetime
    total_requests: int = 0
    requests_per_minute: float = 0.0
    endpoints_accessed: Set[str] = field(default_factory=set)
    failed_requests: int = 0
    recent_requests: deque = field(default_factory=lambda: deque(maxlen=1000))
    is_blocked: bool = False
    block_reason: Optional[str] = None
    block_action: Optional[BlockAction] = None
    block_time: Optional[datetime] = None
    unblock_time: Optional[datetime] = None
    threat_score: int = 0
    attack_types_detected: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'ip': self.ip,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'total_requests': self.total_requests,
            'requests_per_minute': round(self.requests_per_minute, 2),
            'endpoints_accessed': len(self.endpoints_accessed),
            'endpoint_list': list(self.endpoints_accessed)[:20],
            'failed_requests': self.failed_requests,
            'is_blocked': self.is_blocked,
            'block_reason': self.block_reason,
            'block_action': self.block_action.value if self.block_action else None,
            'block_time': self.block_time.isoformat() if self.block_time else None,
            'unblock_time': self.unblock_time.isoformat() if self.unblock_time else None,
            'threat_score': self.threat_score,
            'attack_types': list(self.attack_types_detected)
        }


@dataclass
class AttackAlert:
    """Alert for a detected attack"""
    id: str
    timestamp: datetime
    source_ip: str
    attack_type: AttackType
    severity: str
    description: str
    request_count: int
    time_window: int  # seconds
    action_taken: BlockAction
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'attack_type': self.attack_type.value,
            'severity': self.severity,
            'description': self.description,
            'request_count': self.request_count,
            'time_window': self.time_window,
            'action_taken': self.action_taken.value,
            'details': self.details
        }


class IPQuarantineSystem:
    """
    Real-time IP monitoring and quarantine system.
    Detects attack patterns and blocks malicious IPs.
    """
    
    # Default thresholds for attack detection
    DEFAULT_THRESHOLDS = {
        'requests_per_minute_warn': 60,      # Warning threshold
        'requests_per_minute_throttle': 100,  # Throttle threshold
        'requests_per_minute_block': 200,    # Block threshold
        'endpoint_scan_threshold': 10,       # Unique endpoints in 1 min
        'failed_requests_threshold': 20,     # Failed requests in 5 min
        'burst_requests': 50,                # Requests in 10 seconds
        'burst_window': 10,                  # Seconds for burst detection
    }
    
    # IPs that should never be blocked
    # localhost is whitelisted for the frontend dashboard
    WHITELIST = {
        '127.0.0.1',
        '::1',
    }
    
    # Block durations
    BLOCK_DURATIONS = {
        BlockAction.WARN: 0,
        BlockAction.THROTTLE: 60,        # 1 minute
        BlockAction.TEMP_BLOCK: 300,     # 5 minutes
        BlockAction.BLOCK: 900,          # 15 minutes
        BlockAction.PERMANENT: None,      # Forever
    }
    
    def __init__(self):
        self.ip_stats: Dict[str, IPRequestStats] = {}
        self.blocked_ips: Dict[str, IPRequestStats] = {}
        self.attack_alerts: deque = deque(maxlen=1000)
        self.thresholds = self.DEFAULT_THRESHOLDS.copy()
        self.whitelist = self.WHITELIST.copy()
        self.lock = Lock()
        
        # Alert callbacks (for WebSocket broadcasting)
        self.alert_callbacks: List[Callable] = []
        
        # Statistics
        self.total_blocked = 0
        self.total_attacks_detected = 0
        self.alerts_by_type: Dict[str, int] = defaultdict(int)
        
        # Auto-unblock task handle
        self._cleanup_task = None
        
    def add_alert_callback(self, callback: Callable):
        """Add callback to be called when attack is detected"""
        self.alert_callbacks.append(callback)
        
    def add_to_whitelist(self, ip: str):
        """Add IP to whitelist (never block)"""
        self.whitelist.add(ip)
        # If currently blocked, unblock
        if ip in self.blocked_ips:
            self.unblock_ip(ip)
            
    def remove_from_whitelist(self, ip: str):
        """Remove IP from whitelist"""
        self.whitelist.discard(ip)
        
    def set_threshold(self, key: str, value: int):
        """Update a detection threshold"""
        if key in self.thresholds:
            self.thresholds[key] = value
            logger.info(f"Updated threshold {key} = {value}")
            
    def record_request(self, ip: str, endpoint: str, status_code: int = 200) -> Dict[str, Any]:
        """
        Record a request from an IP and check for attack patterns.
        Returns detection result with any actions to take.
        """
        now = datetime.now(timezone.utc)
        
        # Normalize IP
        ip = self._normalize_ip(ip)
        
        # Check if IP is whitelisted
        if ip in self.whitelist:
            return {'allowed': True, 'blocked': False, 'reason': 'whitelisted'}
            
        # Check if already blocked
        if ip in self.blocked_ips:
            blocked_stats = self.blocked_ips[ip]
            
            # Check if block has expired
            if blocked_stats.unblock_time and now >= blocked_stats.unblock_time:
                self.unblock_ip(ip)
            else:
                return {
                    'allowed': False,
                    'blocked': True,
                    'reason': blocked_stats.block_reason,
                    'unblock_time': blocked_stats.unblock_time.isoformat() if blocked_stats.unblock_time else None
                }
        
        with self.lock:
            # Get or create IP stats
            if ip not in self.ip_stats:
                self.ip_stats[ip] = IPRequestStats(
                    ip=ip,
                    first_seen=now,
                    last_seen=now
                )
            
            stats = self.ip_stats[ip]
            stats.last_seen = now
            stats.total_requests += 1
            stats.endpoints_accessed.add(endpoint)
            
            # Record request timestamp
            stats.recent_requests.append({
                'time': now,
                'endpoint': endpoint,
                'status': status_code
            })
            
            # Track failed requests
            if status_code >= 400:
                stats.failed_requests += 1
            
            # Calculate requests per minute
            stats.requests_per_minute = self._calculate_rpm(stats)
            
        # Check for attacks
        detection_result = self._detect_attacks(stats)
        
        return detection_result
        
    def _normalize_ip(self, ip: str) -> str:
        """Normalize IP address format"""
        if ip.startswith('::ffff:'):
            ip = ip[7:]  # Remove IPv6-mapped IPv4 prefix
        return ip
        
    def _calculate_rpm(self, stats: IPRequestStats) -> float:
        """Calculate requests per minute based on recent requests"""
        now = datetime.now(timezone.utc)
        one_minute_ago = now - timedelta(minutes=1)
        
        recent_count = sum(
            1 for req in stats.recent_requests 
            if req['time'] >= one_minute_ago
        )
        
        return float(recent_count)
        
    def _detect_attacks(self, stats: IPRequestStats) -> Dict[str, Any]:
        """Detect attack patterns from IP statistics"""
        now = datetime.now(timezone.utc)
        result = {'allowed': True, 'blocked': False, 'alerts': []}
        
        # 1. Check for DOS flood (high request rate)
        rpm = stats.requests_per_minute
        
        if rpm >= self.thresholds['requests_per_minute_block']:
            alert = self._create_attack_alert(
                stats, AttackType.DOS_FLOOD, 'CRITICAL',
                f"Flood attack detected: {rpm:.0f} requests/min from {stats.ip}",
                BlockAction.BLOCK
            )
            self._block_ip(stats, BlockAction.BLOCK, "DOS flood detected")
            result['blocked'] = True
            result['allowed'] = False
            result['alerts'].append(alert)
            
        elif rpm >= self.thresholds['requests_per_minute_throttle']:
            alert = self._create_attack_alert(
                stats, AttackType.RATE_LIMIT_EXCEEDED, 'HIGH',
                f"High request rate: {rpm:.0f} requests/min from {stats.ip}",
                BlockAction.THROTTLE
            )
            self._block_ip(stats, BlockAction.THROTTLE, "Rate limit exceeded")
            result['blocked'] = True
            result['allowed'] = False
            result['alerts'].append(alert)
            
        elif rpm >= self.thresholds['requests_per_minute_warn']:
            alert = self._create_attack_alert(
                stats, AttackType.RATE_LIMIT_EXCEEDED, 'MEDIUM',
                f"Elevated request rate: {rpm:.0f} requests/min from {stats.ip}",
                BlockAction.WARN
            )
            result['alerts'].append(alert)
        
        # 2. Check for endpoint scanning (recon)
        if not result['blocked']:
            one_minute_ago = now - timedelta(minutes=1)
            recent_endpoints = set()
            for req in stats.recent_requests:
                if req['time'] >= one_minute_ago:
                    recent_endpoints.add(req['endpoint'])
            
            if len(recent_endpoints) >= self.thresholds['endpoint_scan_threshold']:
                alert = self._create_attack_alert(
                    stats, AttackType.ENDPOINT_SCAN, 'HIGH',
                    f"Endpoint scan detected: {len(recent_endpoints)} unique endpoints from {stats.ip}",
                    BlockAction.TEMP_BLOCK
                )
                self._block_ip(stats, BlockAction.TEMP_BLOCK, "Endpoint scanning detected")
                result['blocked'] = True
                result['allowed'] = False
                result['alerts'].append(alert)
        
        # 3. Check for burst requests (sudden spike)
        if not result['blocked']:
            burst_window = now - timedelta(seconds=self.thresholds['burst_window'])
            burst_count = sum(
                1 for req in stats.recent_requests 
                if req['time'] >= burst_window
            )
            
            if burst_count >= self.thresholds['burst_requests']:
                alert = self._create_attack_alert(
                    stats, AttackType.DOS_FLOOD, 'HIGH',
                    f"Request burst detected: {burst_count} requests in {self.thresholds['burst_window']}s from {stats.ip}",
                    BlockAction.TEMP_BLOCK
                )
                self._block_ip(stats, BlockAction.TEMP_BLOCK, "Request burst detected")
                result['blocked'] = True
                result['allowed'] = False
                result['alerts'].append(alert)
        
        # 4. Check for brute force (many failed requests)
        if not result['blocked']:
            five_minutes_ago = now - timedelta(minutes=5)
            recent_failures = sum(
                1 for req in stats.recent_requests 
                if req['time'] >= five_minutes_ago and req['status'] >= 400
            )
            
            if recent_failures >= self.thresholds['failed_requests_threshold']:
                alert = self._create_attack_alert(
                    stats, AttackType.BRUTE_FORCE, 'HIGH',
                    f"Possible brute force: {recent_failures} failed requests from {stats.ip}",
                    BlockAction.BLOCK
                )
                self._block_ip(stats, BlockAction.BLOCK, "Brute force attempt detected")
                result['blocked'] = True
                result['allowed'] = False
                result['alerts'].append(alert)
        
        # Notify callbacks for alerts
        for alert in result['alerts']:
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    logger.error(f"Alert callback error: {e}")
        
        return result
        
    def _create_attack_alert(self, stats: IPRequestStats, attack_type: AttackType,
                            severity: str, description: str, 
                            action: BlockAction) -> AttackAlert:
        """Create an attack alert"""
        alert_id = f"IP-ATK-{int(datetime.now().timestamp())}-{stats.ip.replace('.', '-')}"
        
        alert = AttackAlert(
            id=alert_id,
            timestamp=datetime.now(timezone.utc),
            source_ip=stats.ip,
            attack_type=attack_type,
            severity=severity,
            description=description,
            request_count=stats.total_requests,
            time_window=60,
            action_taken=action,
            details={
                'requests_per_minute': stats.requests_per_minute,
                'endpoints_accessed': len(stats.endpoints_accessed),
                'failed_requests': stats.failed_requests,
                'total_requests': stats.total_requests
            }
        )
        
        self.attack_alerts.append(alert)
        self.total_attacks_detected += 1
        self.alerts_by_type[attack_type.value] += 1
        
        stats.attack_types_detected.add(attack_type.value)
        stats.threat_score += self._get_severity_score(severity)
        
        logger.warning(f"🚨 ATTACK DETECTED: {description} | Action: {action.value}")
        
        return alert
        
    def _get_severity_score(self, severity: str) -> int:
        """Get numeric score for severity"""
        scores = {'LOW': 1, 'MEDIUM': 3, 'HIGH': 5, 'CRITICAL': 10}
        return scores.get(severity, 1)
        
    def _block_ip(self, stats: IPRequestStats, action: BlockAction, reason: str):
        """Block an IP address"""
        now = datetime.now(timezone.utc)
        
        stats.is_blocked = True
        stats.block_reason = reason
        stats.block_action = action
        stats.block_time = now
        
        # Set unblock time based on action
        duration = self.BLOCK_DURATIONS.get(action)
        if duration:
            stats.unblock_time = now + timedelta(seconds=duration)
        else:
            stats.unblock_time = None  # Permanent
        
        self.blocked_ips[stats.ip] = stats
        self.total_blocked += 1
        
        logger.info(f"🛑 BLOCKED IP: {stats.ip} | Reason: {reason} | Action: {action.value}")
        
    def unblock_ip(self, ip: str) -> bool:
        """Manually unblock an IP address"""
        ip = self._normalize_ip(ip)
        
        if ip in self.blocked_ips:
            stats = self.blocked_ips[ip]
            stats.is_blocked = False
            stats.block_reason = None
            stats.block_action = None
            stats.block_time = None
            stats.unblock_time = None
            
            del self.blocked_ips[ip]
            logger.info(f"✅ UNBLOCKED IP: {ip}")
            return True
        return False
        
    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked"""
        ip = self._normalize_ip(ip)
        
        if ip in self.blocked_ips:
            stats = self.blocked_ips[ip]
            # Check if block has expired
            if stats.unblock_time and datetime.now(timezone.utc) >= stats.unblock_time:
                self.unblock_ip(ip)
                return False
            return True
        return False
        
    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """Get all currently blocked IPs"""
        # First cleanup expired blocks
        self._cleanup_expired_blocks()
        return [stats.to_dict() for stats in self.blocked_ips.values()]
        
    def get_ip_stats(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get statistics for a specific IP"""
        ip = self._normalize_ip(ip)
        if ip in self.ip_stats:
            return self.ip_stats[ip].to_dict()
        return None
        
    def get_all_ip_stats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get statistics for all tracked IPs"""
        # Sort by request count (most active first)
        sorted_ips = sorted(
            self.ip_stats.values(),
            key=lambda x: x.total_requests,
            reverse=True
        )
        return [stats.to_dict() for stats in sorted_ips[:limit]]
        
    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent attack alerts"""
        alerts = list(self.attack_alerts)
        alerts.reverse()  # Most recent first
        return [alert.to_dict() for alert in alerts[:limit]]
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall quarantine system statistics"""
        return {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'total_ips_tracked': len(self.ip_stats),
            'currently_blocked': len(self.blocked_ips),
            'total_blocked_ever': self.total_blocked,
            'total_attacks_detected': self.total_attacks_detected,
            'alerts_by_type': dict(self.alerts_by_type),
            'thresholds': self.thresholds,
            'whitelist_count': len(self.whitelist)
        }
        
    def _cleanup_expired_blocks(self):
        """Clean up expired temporary blocks"""
        now = datetime.now(timezone.utc)
        expired = []
        
        for ip, stats in self.blocked_ips.items():
            if stats.unblock_time and now >= stats.unblock_time:
                expired.append(ip)
        
        for ip in expired:
            self.unblock_ip(ip)
            
    async def auto_cleanup_task(self):
        """Background task to cleanup expired blocks"""
        while True:
            await asyncio.sleep(30)  # Check every 30 seconds
            self._cleanup_expired_blocks()
            
    def reset_ip_stats(self, ip: str) -> bool:
        """Reset statistics for an IP (after unblocking)"""
        ip = self._normalize_ip(ip)
        if ip in self.ip_stats:
            del self.ip_stats[ip]
            return True
        return False
        
    def clear_all_blocks(self):
        """Clear all blocked IPs (emergency reset)"""
        for ip in list(self.blocked_ips.keys()):
            self.unblock_ip(ip)
        logger.warning("⚠️ All IP blocks cleared!")


# Global instance
ip_quarantine = IPQuarantineSystem()


def get_ip_quarantine() -> IPQuarantineSystem:
    return ip_quarantine
