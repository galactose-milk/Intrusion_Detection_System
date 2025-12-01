# backend/app/attack_detector.py
"""
Advanced Attack Detection Module for Intrusion Detection System
Implements pattern-based and behavioral detection for various attack types
"""

import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
import re
import hashlib
import ipaddress

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AttackType(Enum):
    """Types of attacks detected"""
    PORT_SCAN = "Port Scan"
    SYN_FLOOD = "SYN Flood (DoS)"
    BRUTE_FORCE = "Brute Force"
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    COMMAND_INJECTION = "Command Injection"
    PATH_TRAVERSAL = "Path Traversal"
    DDoS = "Distributed Denial of Service"
    ARP_SPOOFING = "ARP Spoofing"
    DNS_TUNNELING = "DNS Tunneling"
    DATA_EXFILTRATION = "Data Exfiltration"
    MALWARE_COMMUNICATION = "Malware C2 Communication"
    PRIVILEGE_ESCALATION = "Privilege Escalation Attempt"
    LATERAL_MOVEMENT = "Lateral Movement"
    RECONNAISSANCE = "Network Reconnaissance"


class Severity(Enum):
    """Alert severity levels"""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class SecurityAlert:
    """Security alert data class"""
    id: str
    timestamp: datetime
    attack_type: AttackType
    severity: Severity
    source_ip: str
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    description: str
    indicators: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    mitre_tactics: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'attack_type': self.attack_type.value,
            'severity': self.severity.value,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'description': self.description,
            'indicators': self.indicators,
            'confidence': self.confidence,
            'mitre_tactics': self.mitre_tactics,
            'recommended_actions': self.recommended_actions
        }


class PortScanDetector:
    """Detect port scanning activities"""
    
    def __init__(self, 
                 vertical_threshold: int = 15,  # ports per target in time window
                 horizontal_threshold: int = 10,  # targets per source in time window
                 time_window: int = 60):  # seconds
        self.vertical_threshold = vertical_threshold
        self.horizontal_threshold = horizontal_threshold
        self.time_window = time_window
        
        # Track: source_ip -> {target_ip: [ports accessed]}
        self.vertical_scans = defaultdict(lambda: defaultdict(list))
        # Track: source_ip -> [target_ips accessed]
        self.horizontal_scans = defaultdict(list)
        # Timestamps
        self.scan_times = defaultdict(list)
        
    def analyze(self, src_ip: str, dst_ip: str, dst_port: int) -> Optional[SecurityAlert]:
        """Analyze connection for port scan patterns"""
        now = time.time()
        
        # Clean old data
        self._cleanup_old_data(now)
        
        # Track this connection
        self.vertical_scans[src_ip][dst_ip].append((dst_port, now))
        self.horizontal_scans[src_ip].append((dst_ip, now))
        self.scan_times[src_ip].append(now)
        
        # Check for vertical scan (many ports on one target)
        unique_ports = set(p for p, t in self.vertical_scans[src_ip][dst_ip] 
                          if now - t < self.time_window)
        
        if len(unique_ports) >= self.vertical_threshold:
            return self._create_alert(
                src_ip, dst_ip, 
                f"Vertical port scan detected: {len(unique_ports)} ports scanned on {dst_ip}",
                unique_ports,
                scan_type="vertical"
            )
        
        # Check for horizontal scan (same port on many targets)
        unique_targets = set(ip for ip, t in self.horizontal_scans[src_ip] 
                            if now - t < self.time_window)
        
        if len(unique_targets) >= self.horizontal_threshold:
            return self._create_alert(
                src_ip, None,
                f"Horizontal scan detected: {len(unique_targets)} hosts scanned",
                set(),
                scan_type="horizontal"
            )
        
        return None
    
    def _cleanup_old_data(self, now: float):
        """Remove data older than time window"""
        cutoff = now - self.time_window * 2
        
        for src_ip in list(self.vertical_scans.keys()):
            for dst_ip in list(self.vertical_scans[src_ip].keys()):
                self.vertical_scans[src_ip][dst_ip] = [
                    (p, t) for p, t in self.vertical_scans[src_ip][dst_ip]
                    if t > cutoff
                ]
        
        for src_ip in list(self.horizontal_scans.keys()):
            self.horizontal_scans[src_ip] = [
                (ip, t) for ip, t in self.horizontal_scans[src_ip]
                if t > cutoff
            ]
    
    def _create_alert(self, src_ip: str, dst_ip: Optional[str], 
                     description: str, ports: set, scan_type: str) -> SecurityAlert:
        """Create port scan alert"""
        alert_id = hashlib.md5(
            f"{src_ip}:{dst_ip}:{scan_type}:{time.time()}".encode()
        ).hexdigest()[:12]
        
        return SecurityAlert(
            id=f"PS-{alert_id}",
            timestamp=datetime.now(timezone.utc),
            attack_type=AttackType.PORT_SCAN,
            severity=Severity.HIGH if scan_type == "horizontal" else Severity.MEDIUM,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=None,
            destination_port=None,
            description=description,
            indicators=[
                f"Scan type: {scan_type}",
                f"Ports scanned: {len(ports)}" if ports else "Multiple targets",
            ],
            confidence=0.85,
            mitre_tactics=["TA0043 - Reconnaissance", "TA0007 - Discovery"],
            recommended_actions=[
                f"Block source IP {src_ip} at firewall",
                "Review target systems for unauthorized access",
                "Enable enhanced logging on affected systems"
            ]
        )


class BruteForceDetector:
    """Detect brute force login attempts"""
    
    def __init__(self,
                 threshold: int = 5,  # failed attempts before alert
                 time_window: int = 300,  # 5 minutes
                 lockout_threshold: int = 10):  # attempts before recommending lockout
        self.threshold = threshold
        self.time_window = time_window
        self.lockout_threshold = lockout_threshold
        
        # Track: (src_ip, target_service) -> [attempt_times]
        self.attempts = defaultdict(list)
        # Track successful logins after failures
        self.success_after_fail = defaultdict(int)
        
    def record_attempt(self, src_ip: str, dst_ip: str, service: str, 
                       success: bool) -> Optional[SecurityAlert]:
        """Record a login attempt and check for brute force"""
        now = time.time()
        key = (src_ip, f"{dst_ip}:{service}")
        
        # Clean old attempts
        self.attempts[key] = [t for t in self.attempts[key] 
                              if now - t < self.time_window]
        
        if not success:
            self.attempts[key].append(now)
            
            if len(self.attempts[key]) >= self.threshold:
                severity = Severity.CRITICAL if len(self.attempts[key]) >= self.lockout_threshold else Severity.HIGH
                
                alert_id = hashlib.md5(
                    f"{src_ip}:{dst_ip}:{service}:{now}".encode()
                ).hexdigest()[:12]
                
                return SecurityAlert(
                    id=f"BF-{alert_id}",
                    timestamp=datetime.now(timezone.utc),
                    attack_type=AttackType.BRUTE_FORCE,
                    severity=severity,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=None,
                    destination_port=self._get_service_port(service),
                    description=f"Brute force attack detected: {len(self.attempts[key])} failed attempts on {service}",
                    indicators=[
                        f"Failed attempts: {len(self.attempts[key])}",
                        f"Time window: {self.time_window}s",
                        f"Target service: {service}"
                    ],
                    confidence=0.9,
                    mitre_tactics=["TA0006 - Credential Access", "TA0001 - Initial Access"],
                    recommended_actions=[
                        f"Temporarily block {src_ip}",
                        f"Implement account lockout on {service}",
                        "Enable MFA if not already active",
                        "Review authentication logs"
                    ]
                )
        else:
            # Track if success after multiple failures (might indicate successful breach)
            if len(self.attempts[key]) >= 3:
                self.success_after_fail[key] += 1
        
        return None
    
    def _get_service_port(self, service: str) -> Optional[int]:
        """Get common port for service"""
        ports = {
            'ssh': 22, 'ftp': 21, 'telnet': 23,
            'rdp': 3389, 'smb': 445, 'mysql': 3306,
            'postgres': 5432, 'http': 80, 'https': 443
        }
        return ports.get(service.lower())


class DoSDetector:
    """Detect Denial of Service attacks"""
    
    def __init__(self,
                 syn_threshold: int = 100,  # SYN packets per second
                 packet_threshold: int = 1000,  # packets per second
                 bandwidth_threshold: int = 100_000_000,  # 100 Mbps
                 time_window: int = 10):  # seconds
        self.syn_threshold = syn_threshold
        self.packet_threshold = packet_threshold
        self.bandwidth_threshold = bandwidth_threshold
        self.time_window = time_window
        
        # Track: target_ip -> [(timestamp, packet_size, is_syn)]
        self.traffic = defaultdict(lambda: deque(maxlen=50000))
        # Track unique sources per target for DDoS
        self.sources_per_target = defaultdict(set)
        
    def record_packet(self, src_ip: str, dst_ip: str, 
                      packet_size: int, is_syn: bool = False) -> Optional[SecurityAlert]:
        """Record packet and check for DoS patterns"""
        now = time.time()
        
        self.traffic[dst_ip].append((now, packet_size, is_syn, src_ip))
        self.sources_per_target[dst_ip].add(src_ip)
        
        # Analyze traffic to this destination
        return self._analyze_target(dst_ip, now)
    
    def _analyze_target(self, dst_ip: str, now: float) -> Optional[SecurityAlert]:
        """Analyze traffic patterns to a target"""
        # Get recent traffic
        recent = [(t, size, syn, src) for t, size, syn, src in self.traffic[dst_ip]
                  if now - t < self.time_window]
        
        if not recent:
            return None
        
        # Calculate metrics
        elapsed = now - recent[0][0] if len(recent) > 1 else 1
        elapsed = max(elapsed, 0.1)  # Avoid division by zero
        
        packet_rate = len(recent) / elapsed
        syn_count = sum(1 for _, _, syn, _ in recent if syn)
        syn_rate = syn_count / elapsed
        total_bytes = sum(size for _, size, _, _ in recent)
        bandwidth = total_bytes / elapsed
        unique_sources = len(set(src for _, _, _, src in recent))
        
        # Check for SYN flood
        if syn_rate > self.syn_threshold:
            return self._create_dos_alert(
                dst_ip, 
                AttackType.SYN_FLOOD,
                f"SYN flood detected: {syn_rate:.0f} SYN/sec",
                unique_sources,
                syn_rate
            )
        
        # Check for volumetric attack
        if packet_rate > self.packet_threshold or bandwidth > self.bandwidth_threshold:
            attack_type = AttackType.DDoS if unique_sources > 10 else AttackType.SYN_FLOOD
            return self._create_dos_alert(
                dst_ip,
                attack_type,
                f"Volumetric attack: {packet_rate:.0f} pkt/s, {bandwidth/1_000_000:.1f} Mbps",
                unique_sources,
                packet_rate
            )
        
        return None
    
    def _create_dos_alert(self, dst_ip: str, attack_type: AttackType,
                         description: str, unique_sources: int, rate: float) -> SecurityAlert:
        """Create DoS/DDoS alert"""
        alert_id = hashlib.md5(
            f"{dst_ip}:{attack_type.value}:{time.time()}".encode()
        ).hexdigest()[:12]
        
        is_distributed = unique_sources > 10
        severity = Severity.CRITICAL if is_distributed else Severity.HIGH
        
        return SecurityAlert(
            id=f"DOS-{alert_id}",
            timestamp=datetime.now(timezone.utc),
            attack_type=attack_type,
            severity=severity,
            source_ip="Multiple" if is_distributed else "Unknown",
            destination_ip=dst_ip,
            source_port=None,
            destination_port=None,
            description=description,
            indicators=[
                f"Unique sources: {unique_sources}",
                f"Attack rate: {rate:.0f} packets/sec",
                "Distributed attack" if is_distributed else "Single source"
            ],
            confidence=0.92,
            mitre_tactics=["TA0040 - Impact"],
            recommended_actions=[
                "Enable rate limiting",
                "Activate DDoS mitigation",
                "Contact ISP for upstream filtering" if is_distributed else "Block source IP",
                "Enable SYN cookies"
            ]
        )


class PayloadAnalyzer:
    """Analyze packet payloads for malicious content"""
    
    # SQL Injection patterns
    SQL_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"((\%27)|(\'))union",
        r"exec(\s|\+)+(s|x)p\w+",
        r"UNION(\s+)SELECT",
        r"SELECT.*FROM.*WHERE",
        r"INSERT(\s+)INTO",
        r"DELETE(\s+)FROM",
        r"DROP(\s+)TABLE",
        r"UPDATE(\s+)\w+(\s+)SET",
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<img[^>]+onerror",
        r"<svg[^>]+onload",
        r"eval\s*\(",
        r"document\.cookie",
        r"document\.write",
        r"innerHTML",
    ]
    
    # Command injection patterns
    CMD_PATTERNS = [
        r";\s*(cat|ls|pwd|whoami|id|uname)",
        r"\|\s*(cat|ls|pwd|whoami|id|uname)",
        r"`.*`",
        r"\$\(.*\)",
        r"&&\s*(cat|ls|pwd|whoami|id)",
        r"/bin/(bash|sh|zsh)",
        r"cmd\.exe",
        r"powershell",
    ]
    
    # Path traversal patterns
    TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"\.\.%2f",
        r"%2e%2e%5c",
        r"/etc/passwd",
        r"/etc/shadow",
        r"c:\\windows",
        r"c:/windows",
    ]
    
    def __init__(self):
        # Compile patterns for efficiency
        self.sql_compiled = [re.compile(p, re.IGNORECASE) for p in self.SQL_PATTERNS]
        self.xss_compiled = [re.compile(p, re.IGNORECASE) for p in self.XSS_PATTERNS]
        self.cmd_compiled = [re.compile(p, re.IGNORECASE) for p in self.CMD_PATTERNS]
        self.traversal_compiled = [re.compile(p, re.IGNORECASE) for p in self.TRAVERSAL_PATTERNS]
    
    def analyze(self, payload: bytes, src_ip: str, dst_ip: str, 
                dst_port: int) -> List[SecurityAlert]:
        """Analyze payload for malicious patterns"""
        alerts = []
        
        try:
            # Try to decode as string
            text = payload.decode('utf-8', errors='ignore')
        except:
            return alerts
        
        # Check SQL Injection
        for pattern in self.sql_compiled:
            if pattern.search(text):
                alerts.append(self._create_alert(
                    AttackType.SQL_INJECTION,
                    src_ip, dst_ip, dst_port,
                    "SQL Injection attempt detected",
                    pattern.pattern
                ))
                break
        
        # Check XSS
        for pattern in self.xss_compiled:
            if pattern.search(text):
                alerts.append(self._create_alert(
                    AttackType.XSS,
                    src_ip, dst_ip, dst_port,
                    "Cross-Site Scripting attempt detected",
                    pattern.pattern
                ))
                break
        
        # Check Command Injection
        for pattern in self.cmd_compiled:
            if pattern.search(text):
                alerts.append(self._create_alert(
                    AttackType.COMMAND_INJECTION,
                    src_ip, dst_ip, dst_port,
                    "Command Injection attempt detected",
                    pattern.pattern
                ))
                break
        
        # Check Path Traversal
        for pattern in self.traversal_compiled:
            if pattern.search(text):
                alerts.append(self._create_alert(
                    AttackType.PATH_TRAVERSAL,
                    src_ip, dst_ip, dst_port,
                    "Path Traversal attempt detected",
                    pattern.pattern
                ))
                break
        
        return alerts
    
    def _create_alert(self, attack_type: AttackType, src_ip: str, 
                      dst_ip: str, dst_port: int, description: str,
                      matched_pattern: str) -> SecurityAlert:
        """Create payload-based alert"""
        alert_id = hashlib.md5(
            f"{src_ip}:{dst_ip}:{attack_type.value}:{time.time()}".encode()
        ).hexdigest()[:12]
        
        return SecurityAlert(
            id=f"PAY-{alert_id}",
            timestamp=datetime.now(timezone.utc),
            attack_type=attack_type,
            severity=Severity.HIGH,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=None,
            destination_port=dst_port,
            description=description,
            indicators=[
                f"Pattern matched: {matched_pattern[:50]}...",
                f"Target port: {dst_port}"
            ],
            confidence=0.85,
            mitre_tactics=["TA0001 - Initial Access", "TA0002 - Execution"],
            recommended_actions=[
                f"Block IP {src_ip}",
                "Enable WAF rules",
                "Review application logs",
                "Patch vulnerable applications"
            ]
        )


class DataExfiltrationDetector:
    """Detect potential data exfiltration"""
    
    def __init__(self,
                 bytes_threshold: int = 100_000_000,  # 100 MB
                 time_window: int = 3600):  # 1 hour
        self.bytes_threshold = bytes_threshold
        self.time_window = time_window
        
        # Track: src_ip -> [(timestamp, bytes_out, dst_ip)]
        self.outbound_traffic = defaultdict(list)
        
    def record_outbound(self, src_ip: str, dst_ip: str, 
                        bytes_sent: int) -> Optional[SecurityAlert]:
        """Record outbound traffic and check for exfiltration"""
        now = time.time()
        
        # Clean old data
        self.outbound_traffic[src_ip] = [
            (t, b, d) for t, b, d in self.outbound_traffic[src_ip]
            if now - t < self.time_window
        ]
        
        self.outbound_traffic[src_ip].append((now, bytes_sent, dst_ip))
        
        # Calculate total bytes out
        total_bytes = sum(b for _, b, _ in self.outbound_traffic[src_ip])
        
        if total_bytes > self.bytes_threshold:
            unique_dests = set(d for _, _, d in self.outbound_traffic[src_ip])
            
            alert_id = hashlib.md5(
                f"{src_ip}:exfil:{now}".encode()
            ).hexdigest()[:12]
            
            return SecurityAlert(
                id=f"EXFIL-{alert_id}",
                timestamp=datetime.now(timezone.utc),
                attack_type=AttackType.DATA_EXFILTRATION,
                severity=Severity.CRITICAL,
                source_ip=src_ip,
                destination_ip=list(unique_dests)[0] if len(unique_dests) == 1 else "Multiple",
                source_port=None,
                destination_port=None,
                description=f"Potential data exfiltration: {total_bytes/1_000_000:.1f} MB sent",
                indicators=[
                    f"Total data: {total_bytes/1_000_000:.1f} MB",
                    f"Destinations: {len(unique_dests)}",
                    f"Time window: {self.time_window/3600:.1f} hours"
                ],
                confidence=0.75,
                mitre_tactics=["TA0010 - Exfiltration"],
                recommended_actions=[
                    "Investigate source host immediately",
                    "Check for unauthorized processes",
                    "Review file access logs",
                    "Consider isolating the host"
                ]
            )
        
        return None


class IntrusionDetectionEngine:
    """Main intrusion detection engine combining all detectors"""
    
    def __init__(self):
        self.port_scan_detector = PortScanDetector()
        self.brute_force_detector = BruteForceDetector()
        self.dos_detector = DoSDetector()
        self.payload_analyzer = PayloadAnalyzer()
        self.exfiltration_detector = DataExfiltrationDetector()
        
        # Alert storage
        self.alerts = deque(maxlen=10000)
        self.alert_counts = defaultdict(int)
        
        # Statistics
        self.stats = {
            'packets_analyzed': 0,
            'alerts_generated': 0,
            'attacks_by_type': defaultdict(int),
            'attacks_by_severity': defaultdict(int),
            'top_attackers': defaultdict(int),
            'top_targets': defaultdict(int)
        }
    
    def analyze_packet(self, packet_data: Dict[str, Any]) -> List[SecurityAlert]:
        """Analyze a packet for all attack types"""
        alerts = []
        self.stats['packets_analyzed'] += 1
        
        src_ip = packet_data.get('src_ip', '')
        dst_ip = packet_data.get('dst_ip', '')
        src_port = packet_data.get('src_port')
        dst_port = packet_data.get('dst_port')
        packet_size = packet_data.get('packet_size', 0)
        tcp_flags = packet_data.get('tcp_flags', '')
        payload = packet_data.get('payload', b'')
        
        # Check for port scan
        if dst_port:
            alert = self.port_scan_detector.analyze(src_ip, dst_ip, dst_port)
            if alert:
                alerts.append(alert)
        
        # Check for DoS/DDoS
        is_syn = 'S' in tcp_flags if tcp_flags else False
        alert = self.dos_detector.record_packet(src_ip, dst_ip, packet_size, is_syn)
        if alert:
            alerts.append(alert)
        
        # Check payload for attacks
        if payload:
            payload_alerts = self.payload_analyzer.analyze(
                payload if isinstance(payload, bytes) else payload.encode(),
                src_ip, dst_ip, dst_port or 0
            )
            alerts.extend(payload_alerts)
        
        # Check for data exfiltration
        alert = self.exfiltration_detector.record_outbound(src_ip, dst_ip, packet_size)
        if alert:
            alerts.append(alert)
        
        # Store and track alerts
        for alert in alerts:
            self.alerts.append(alert)
            self.alert_counts[alert.attack_type] += 1
            self.stats['alerts_generated'] += 1
            self.stats['attacks_by_type'][alert.attack_type.value] += 1
            self.stats['attacks_by_severity'][alert.severity.value] += 1
            self.stats['top_attackers'][src_ip] += 1
            self.stats['top_targets'][dst_ip] += 1
        
        return alerts
    
    def record_login_attempt(self, src_ip: str, dst_ip: str, 
                             service: str, success: bool) -> Optional[SecurityAlert]:
        """Record and analyze login attempt"""
        alert = self.brute_force_detector.record_attempt(src_ip, dst_ip, service, success)
        if alert:
            self.alerts.append(alert)
            self.stats['alerts_generated'] += 1
            self.stats['attacks_by_type'][alert.attack_type.value] += 1
            self.stats['attacks_by_severity'][alert.severity.value] += 1
        return alert
    
    def get_recent_alerts(self, limit: int = 100, 
                          severity: Optional[str] = None,
                          attack_type: Optional[str] = None) -> List[Dict]:
        """Get recent alerts with optional filtering"""
        alerts = list(self.alerts)
        
        if severity:
            alerts = [a for a in alerts if a.severity.value == severity]
        
        if attack_type:
            alerts = [a for a in alerts if a.attack_type.value == attack_type]
        
        return [a.to_dict() for a in alerts[-limit:]]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detection statistics"""
        return {
            'packets_analyzed': self.stats['packets_analyzed'],
            'alerts_generated': self.stats['alerts_generated'],
            'attacks_by_type': dict(self.stats['attacks_by_type']),
            'attacks_by_severity': dict(self.stats['attacks_by_severity']),
            'top_attackers': dict(sorted(
                self.stats['top_attackers'].items(),
                key=lambda x: x[1], reverse=True
            )[:10]),
            'top_targets': dict(sorted(
                self.stats['top_targets'].items(),
                key=lambda x: x[1], reverse=True
            )[:10])
        }
    
    def get_threat_summary(self) -> Dict[str, Any]:
        """Get threat summary for dashboard"""
        now = datetime.now(timezone.utc)
        
        # Alerts in last hour
        hour_ago = now - timedelta(hours=1)
        recent_alerts = [a for a in self.alerts 
                        if a.timestamp > hour_ago]
        
        severity_counts = defaultdict(int)
        for alert in recent_alerts:
            severity_counts[alert.severity.value] += 1
        
        return {
            'total_alerts_1h': len(recent_alerts),
            'critical_alerts': severity_counts.get('CRITICAL', 0),
            'high_alerts': severity_counts.get('HIGH', 0),
            'medium_alerts': severity_counts.get('MEDIUM', 0),
            'low_alerts': severity_counts.get('LOW', 0),
            'most_common_attack': max(
                self.stats['attacks_by_type'].items(),
                key=lambda x: x[1],
                default=('None', 0)
            )[0],
            'top_attacker': max(
                self.stats['top_attackers'].items(),
                key=lambda x: x[1],
                default=('None', 0)
            )[0]
        }


# Global instance
intrusion_engine = IntrusionDetectionEngine()


def get_intrusion_engine() -> IntrusionDetectionEngine:
    """Get global intrusion detection engine"""
    return intrusion_engine
