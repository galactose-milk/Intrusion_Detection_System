# backend/app/real_packet_capture.py
"""
Real Packet Capture Module for Intrusion Detection System
Uses scapy for actual network traffic capture and analysis
"""

import threading
import time
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Callable
from collections import defaultdict, deque
import socket
import struct
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import scapy - it may require root privileges for packet capture
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available - packet capture will be limited")


class PacketAnalyzer:
    """Analyze individual packets for security threats"""
    
    # Common attack signatures
    SUSPICIOUS_PORTS = {
        23: "Telnet",
        135: "RPC",
        139: "NetBIOS",
        445: "SMB",
        1433: "MSSQL",
        3306: "MySQL", 
        3389: "RDP",
        5900: "VNC",
        6379: "Redis",
        27017: "MongoDB",
        11211: "Memcached"
    }
    
    # Known malicious patterns
    ATTACK_SIGNATURES = {
        b"GET /shell": "Web Shell Access",
        b"POST /admin": "Admin Brute Force",
        b"cmd.exe": "Command Injection",
        b"/etc/passwd": "LFI Attack",
        b"<script>": "XSS Attempt",
        b"' OR '1'='1": "SQL Injection",
        b"UNION SELECT": "SQL Injection",
        b"../../../../": "Path Traversal",
        b"eval(": "Code Injection",
        b"exec(": "Code Injection",
    }
    
    # SYN flood detection threshold
    SYN_THRESHOLD = 100  # SYN packets per second from single source
    
    def __init__(self):
        self.syn_counts = defaultdict(lambda: deque(maxlen=1000))
        self.connection_attempts = defaultdict(list)
        
    def analyze_packet(self, packet) -> Dict[str, Any]:
        """Analyze a packet and return security analysis"""
        result = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'is_suspicious': False,
            'threat_type': None,
            'severity': 'LOW',
            'indicators': []
        }
        
        if not packet.haslayer(IP):
            return result
            
        ip_layer = packet[IP]
        result['src_ip'] = ip_layer.src
        result['dst_ip'] = ip_layer.dst
        result['protocol'] = ip_layer.proto
        result['packet_size'] = len(packet)
        result['ttl'] = ip_layer.ttl
        
        # TCP Analysis
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            result['src_port'] = tcp_layer.sport
            result['dst_port'] = tcp_layer.dport
            result['tcp_flags'] = str(tcp_layer.flags)
            
            # Check for SYN flood
            if tcp_layer.flags == 'S':  # SYN flag
                self._track_syn(ip_layer.src)
                if self._is_syn_flood(ip_layer.src):
                    result['is_suspicious'] = True
                    result['threat_type'] = 'SYN Flood Attack'
                    result['severity'] = 'CRITICAL'
                    result['indicators'].append('Excessive SYN packets detected')
            
            # Check for port scan (SYN to multiple ports)
            if tcp_layer.flags == 'S':
                self._track_connection_attempt(ip_layer.src, tcp_layer.dport)
                if self._is_port_scan(ip_layer.src):
                    result['is_suspicious'] = True
                    result['threat_type'] = 'Port Scan'
                    result['severity'] = 'HIGH'
                    result['indicators'].append('Multiple ports probed from same source')
            
            # Check suspicious ports
            if tcp_layer.dport in self.SUSPICIOUS_PORTS:
                result['is_suspicious'] = True
                result['threat_type'] = f'Suspicious Port Access: {self.SUSPICIOUS_PORTS[tcp_layer.dport]}'
                result['severity'] = 'MEDIUM'
                result['indicators'].append(f'Connection to {self.SUSPICIOUS_PORTS[tcp_layer.dport]} port')
            
            # Check for payload attacks
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                for signature, attack_type in self.ATTACK_SIGNATURES.items():
                    if signature.lower() in payload.lower():
                        result['is_suspicious'] = True
                        result['threat_type'] = attack_type
                        result['severity'] = 'CRITICAL'
                        result['indicators'].append(f'Malicious payload detected: {attack_type}')
                        break
        
        # UDP Analysis
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            result['src_port'] = udp_layer.sport
            result['dst_port'] = udp_layer.dport
            
            # DNS Amplification detection
            if udp_layer.sport == 53 and len(packet) > 512:
                result['is_suspicious'] = True
                result['threat_type'] = 'Possible DNS Amplification'
                result['severity'] = 'HIGH'
                result['indicators'].append('Large DNS response detected')
        
        # ICMP Analysis
        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            result['icmp_type'] = icmp_layer.type
            result['icmp_code'] = icmp_layer.code
            
            # Ping flood detection
            if icmp_layer.type == 8:  # Echo request
                result['is_suspicious'] = True
                result['threat_type'] = 'ICMP Probe'
                result['severity'] = 'LOW'
                result['indicators'].append('ICMP echo request')
        
        # ARP Spoofing detection
        if packet.haslayer(ARP):
            arp_layer = packet[ARP]
            if arp_layer.op == 2:  # ARP reply
                result['is_suspicious'] = True
                result['threat_type'] = 'Possible ARP Spoofing'
                result['severity'] = 'HIGH'
                result['indicators'].append('Unsolicited ARP reply detected')
        
        return result
    
    def _track_syn(self, src_ip: str):
        """Track SYN packets for flood detection"""
        self.syn_counts[src_ip].append(time.time())
    
    def _is_syn_flood(self, src_ip: str) -> bool:
        """Check if source IP is performing SYN flood"""
        now = time.time()
        recent = [t for t in self.syn_counts[src_ip] if now - t < 1.0]
        return len(recent) > self.SYN_THRESHOLD
    
    def _track_connection_attempt(self, src_ip: str, dst_port: int):
        """Track connection attempts for port scan detection"""
        now = time.time()
        self.connection_attempts[src_ip].append((dst_port, now))
        # Clean old entries
        self.connection_attempts[src_ip] = [
            (port, t) for port, t in self.connection_attempts[src_ip]
            if now - t < 60  # Last 60 seconds
        ]
    
    def _is_port_scan(self, src_ip: str) -> bool:
        """Check if source IP is performing port scan"""
        if src_ip not in self.connection_attempts:
            return False
        unique_ports = set(port for port, _ in self.connection_attempts[src_ip])
        return len(unique_ports) > 20  # More than 20 different ports in 60 seconds


class RealPacketCapture:
    """Real-time packet capture using scapy"""
    
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.is_capturing = False
        self.capture_thread = None
        self.packet_queue = deque(maxlen=10000)
        self.analyzer = PacketAnalyzer()
        self.callbacks: List[Callable] = []
        
        # Statistics
        self.stats = {
            'packets_captured': 0,
            'suspicious_packets': 0,
            'bytes_processed': 0,
            'start_time': None,
            'protocols': defaultdict(int),
            'top_talkers': defaultdict(int),
            'attack_counts': defaultdict(int)
        }
    
    def add_callback(self, callback: Callable):
        """Add callback for real-time packet notifications"""
        self.callbacks.append(callback)
    
    def start_capture(self, filter_str: str = None, count: int = 0):
        """Start packet capture in background thread"""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available - cannot start packet capture")
            return False
        
        if self.is_capturing:
            logger.warning("Packet capture already running")
            return False
        
        self.is_capturing = True
        self.stats['start_time'] = datetime.now(timezone.utc)
        
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(filter_str, count),
            daemon=True
        )
        self.capture_thread.start()
        logger.info(f"Started packet capture on interface: {self.interface or 'default'}")
        return True
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        logger.info("Stopped packet capture")
    
    def _capture_loop(self, filter_str: str, count: int):
        """Main capture loop"""
        try:
            sniff(
                iface=self.interface,
                filter=filter_str,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self.is_capturing,
                count=count if count > 0 else 0
            )
        except PermissionError:
            logger.error("Permission denied - packet capture requires root/admin privileges")
        except Exception as e:
            logger.error(f"Error in packet capture: {str(e)}")
    
    def _process_packet(self, packet):
        """Process captured packet"""
        try:
            # Analyze packet
            analysis = self.analyzer.analyze_packet(packet)
            
            # Update statistics
            self.stats['packets_captured'] += 1
            self.stats['bytes_processed'] += len(packet)
            
            if analysis.get('is_suspicious'):
                self.stats['suspicious_packets'] += 1
                if analysis.get('threat_type'):
                    self.stats['attack_counts'][analysis['threat_type']] += 1
            
            # Track protocol distribution
            if packet.haslayer(TCP):
                self.stats['protocols']['TCP'] += 1
            elif packet.haslayer(UDP):
                self.stats['protocols']['UDP'] += 1
            elif packet.haslayer(ICMP):
                self.stats['protocols']['ICMP'] += 1
            
            # Track top talkers
            if 'src_ip' in analysis:
                self.stats['top_talkers'][analysis['src_ip']] += 1
            
            # Add to queue
            self.packet_queue.append(analysis)
            
            # Notify callbacks
            for callback in self.callbacks:
                try:
                    callback(analysis)
                except Exception as e:
                    logger.error(f"Callback error: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")
    
    def get_recent_packets(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent captured packets"""
        return list(self.packet_queue)[-limit:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get capture statistics"""
        runtime = 0
        if self.stats['start_time']:
            runtime = (datetime.now(timezone.utc) - self.stats['start_time']).total_seconds()
        
        return {
            'packets_captured': self.stats['packets_captured'],
            'suspicious_packets': self.stats['suspicious_packets'],
            'bytes_processed': self.stats['bytes_processed'],
            'packets_per_second': self.stats['packets_captured'] / max(runtime, 1),
            'runtime_seconds': runtime,
            'protocol_distribution': dict(self.stats['protocols']),
            'top_talkers': dict(sorted(
                self.stats['top_talkers'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'attack_summary': dict(self.stats['attack_counts'])
        }
    
    def get_suspicious_packets(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get only suspicious packets"""
        return [p for p in list(self.packet_queue) if p.get('is_suspicious')][-limit:]


class ConnectionTracker:
    """Track and analyze network connections in real-time"""
    
    def __init__(self):
        self.active_connections = {}
        self.connection_history = deque(maxlen=10000)
        self.failed_connections = defaultdict(list)
        self.successful_connections = defaultdict(list)
        
    def track_connection(self, src_ip: str, dst_ip: str, src_port: int, 
                         dst_port: int, protocol: str, state: str):
        """Track a network connection"""
        conn_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        now = datetime.now(timezone.utc)
        
        connection = {
            'key': conn_key,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'state': state,
            'first_seen': now.isoformat(),
            'last_seen': now.isoformat(),
            'packet_count': 1
        }
        
        if conn_key in self.active_connections:
            self.active_connections[conn_key]['last_seen'] = now.isoformat()
            self.active_connections[conn_key]['packet_count'] += 1
        else:
            self.active_connections[conn_key] = connection
            self.connection_history.append(connection)
        
        # Track failed vs successful
        if state in ['RST', 'FIN', 'TIMEOUT']:
            self.failed_connections[src_ip].append((dst_ip, dst_port, now))
        elif state == 'ESTABLISHED':
            self.successful_connections[src_ip].append((dst_ip, dst_port, now))
    
    def detect_brute_force(self, threshold: int = 10, window_seconds: int = 60) -> List[Dict]:
        """Detect brute force attempts (many failed connections to same target)"""
        alerts = []
        now = datetime.now(timezone.utc)
        
        for src_ip, attempts in self.failed_connections.items():
            # Filter recent attempts
            recent = [(dst, port, t) for dst, port, t in attempts 
                      if (now - t).total_seconds() < window_seconds]
            
            # Group by destination
            targets = defaultdict(int)
            for dst, port, _ in recent:
                targets[f"{dst}:{port}"] += 1
            
            for target, count in targets.items():
                if count >= threshold:
                    alerts.append({
                        'type': 'Brute Force Attack',
                        'severity': 'HIGH',
                        'src_ip': src_ip,
                        'target': target,
                        'attempt_count': count,
                        'window_seconds': window_seconds,
                        'timestamp': now.isoformat()
                    })
        
        return alerts
    
    def get_active_connections(self) -> List[Dict]:
        """Get all active connections"""
        return list(self.active_connections.values())
    
    def get_connection_summary(self) -> Dict[str, Any]:
        """Get connection summary statistics"""
        return {
            'active_connections': len(self.active_connections),
            'total_tracked': len(self.connection_history),
            'unique_sources': len(set(c['src_ip'] for c in self.connection_history)),
            'unique_destinations': len(set(c['dst_ip'] for c in self.connection_history)),
            'failed_connection_sources': len(self.failed_connections),
            'successful_connection_sources': len(self.successful_connections)
        }


# Global instances
packet_capture = RealPacketCapture()
connection_tracker = ConnectionTracker()


def get_packet_capture() -> RealPacketCapture:
    """Get global packet capture instance"""
    return packet_capture


def get_connection_tracker() -> ConnectionTracker:
    """Get global connection tracker instance"""
    return connection_tracker
