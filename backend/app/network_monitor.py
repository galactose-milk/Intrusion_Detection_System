# backend/app/network_monitor.py
"""
Real Network Monitor for Intrusion Detection System
Monitors actual network connections and system activities - NO SIMULATIONS
"""
import asyncio
import psutil
import socket
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
import logging
from collections import defaultdict, deque
import time
import threading
import struct

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Late import to avoid circular dependency
_login_rate_limiter = None
_packet_analyzer = None

def get_login_rate_limiter():
    """Get login rate limiter with lazy loading to avoid circular imports"""
    global _login_rate_limiter
    if _login_rate_limiter is None:
        try:
            from app.auth import login_rate_limiter
            _login_rate_limiter = login_rate_limiter
        except ImportError:
            logger.warning("Could not import login_rate_limiter - login features disabled")
            _login_rate_limiter = None
    return _login_rate_limiter

def get_packet_analyzer():
    """Get packet analyzer with lazy loading to avoid circular imports"""
    global _packet_analyzer
    if _packet_analyzer is None:
        try:
            from app.real_packet_capture import packet_capture
            _packet_analyzer = packet_capture.analyzer if packet_capture else None
            if _packet_analyzer:
                logger.info("Packet analyzer available for ML feature extraction")
        except ImportError:
            logger.warning("Could not import packet_analyzer - packet-level features disabled")
            _packet_analyzer = None
    return _packet_analyzer

class NetworkMonitor:
    """Monitor REAL network traffic and system activities for intrusion detection"""
    
    def __init__(self):
        self.is_monitoring = False
        self.network_data = deque(maxlen=10000)  # Store last 10k network events
        self.connection_stats = defaultdict(lambda: {'count': 0, 'bytes': 0, 'last_seen': None, 'first_seen': None})
        self.suspicious_activities = []
        self.monitoring_thread = None
        self.target_network_range = None  # Store target network range
        self.monitoring_type = "full"  # Store monitoring type
        
        # Track connection history for analysis
        self.connection_history = defaultdict(list)  # IP -> list of connection events
        self.port_access_history = defaultdict(set)  # IP -> set of ports accessed
        self.bytes_transferred = defaultdict(int)  # IP -> total bytes
        self.previous_connections = {}  # Track previous state for change detection
        
        # ===== NEW: Enhanced tracking for ML features =====
        # Connection duration tracking
        self.connection_start_times = {}  # conn_key -> start_time
        
        # Bytes tracking per connection
        self.prev_net_io = None  # Previous network I/O snapshot
        self.bytes_per_second = defaultdict(float)  # interface -> bytes/sec
        self.packets_per_second = defaultdict(float)  # interface -> packets/sec
        
        # Error rate tracking
        self.connection_errors = defaultdict(int)  # IP -> error count
        self.connection_success = defaultdict(int)  # IP -> success count
        self.syn_errors = defaultdict(int)  # IP -> SYN errors (failed connections)
        self.rej_errors = defaultdict(int)  # IP -> rejection errors
        
        # Service/port statistics
        self.service_access_count = defaultdict(lambda: defaultdict(int))  # IP -> {port: count}
        self.same_service_rate = defaultdict(float)  # IP -> rate of same service access
        
        # Host-based features
        self.dst_host_connections = defaultdict(lambda: defaultdict(int))  # dst_ip -> {src_ip: count}
        self.dst_host_srv_count = defaultdict(lambda: defaultdict(int))  # dst_ip -> {port: count}
        
        # Failed login tracking (from connection patterns)
        self.failed_connection_attempts = defaultdict(int)  # IP -> failed attempts
        
        # ===== NEW: Multi-host and port pattern tracking =====
        # Track which hosts access each service (for srv_diff_host_rate)
        self.service_hosts = defaultdict(lambda: defaultdict(set))  # port -> {service: set of IPs}
        
        # Track source port patterns (for dst_host_same_src_port_rate)
        self.src_port_history = defaultdict(lambda: defaultdict(list))  # dst_ip -> {src_ip: [src_ports]}
        
        # Track service distribution across hosts
        self.host_service_distribution = defaultdict(lambda: defaultdict(set))  # dst_ip -> {port: set of src_ips}
        
        # Outbound command tracking
        self.outbound_commands = defaultdict(int)  # IP -> outbound command count
        self.command_ports = {21, 22, 23, 513, 514, 4444, 5555, 6666, 31337}  # FTP, SSH, Telnet, rsh, syslog, common backdoors
        
        # Global metrics
        self.total_bytes_sent = 0
        self.total_bytes_recv = 0
        self.total_packets_sent = 0
        self.total_packets_recv = 0
        self.last_io_time = None
        
        # ===== NEW: File system monitoring for ML features =====
        self.file_operations = defaultdict(lambda: {
            'file_creations': 0,
            'file_access': 0,
            'shells_opened': 0,
            'last_updated': None
        })
        self.shell_processes = {'bash', 'sh', 'zsh', 'fish', 'csh', 'tcsh', 'ksh', 'dash', 'powershell', 'cmd'}
        self.suspicious_file_ops = []
        
    def start_monitoring(self):
        """Start network monitoring in background thread"""
        if self.is_monitoring:
            logger.warning("Network monitoring is already running")
            return
        
        self.is_monitoring = True
        self.monitoring_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitoring_thread.start()
        logger.info("🔴 REAL Network monitoring started - capturing actual traffic")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        logger.info("Network monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop - REAL traffic only"""
        while self.is_monitoring:
            try:
                # Monitor REAL network connections
                self._monitor_connections()
                
                # Monitor network interface statistics
                self._monitor_network_io()
                
                # Monitor system processes for suspicious activity
                self._monitor_processes()
                
                # Analyze for threats
                self._analyze_connection_patterns()
                
                # Sleep for monitoring interval
                time.sleep(1)  # Monitor every second
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(5)  # Wait before retrying
    
    def _monitor_connections(self):
        """Monitor REAL active network connections with enhanced ML metrics"""
        try:
            connections = psutil.net_connections(kind='inet')
            current_time = datetime.now(timezone.utc)
            current_connections = {}
            
            for conn in connections:
                if conn.laddr:
                    local_ip = conn.laddr.ip
                    local_port = conn.laddr.port
                    
                    remote_ip = conn.raddr.ip if conn.raddr else None
                    remote_port = conn.raddr.port if conn.raddr else None
                    
                    if remote_ip:  # Only track connections with remote addresses
                        conn_key = f"{local_ip}:{local_port}->{remote_ip}:{remote_port}"
                        current_connections[conn_key] = True
                        
                        # Determine if this is a new connection
                        is_new = conn_key not in self.previous_connections
                        
                        # ===== ENHANCED: Track connection start time for duration =====
                        if is_new:
                            self.connection_start_times[conn_key] = current_time
                        
                        # Calculate connection duration
                        start_time = self.connection_start_times.get(conn_key, current_time)
                        connection_duration = (current_time - start_time).total_seconds()
                        
                        # ===== ENHANCED: Track connection status for error rates =====
                        if conn.status in ['SYN_SENT', 'SYN_RECV']:
                            self.syn_errors[remote_ip] += 1
                        elif conn.status == 'ESTABLISHED':
                            self.connection_success[remote_ip] += 1
                        elif conn.status in ['CLOSE_WAIT', 'TIME_WAIT', 'FIN_WAIT1', 'FIN_WAIT2']:
                            pass  # Normal closure
                        elif conn.status in ['NONE', 'CLOSING']:
                            self.connection_errors[remote_ip] += 1
                        
                        # ===== ENHANCED: Service/port tracking =====
                        self.service_access_count[remote_ip][remote_port] += 1
                        
                        # Calculate same service rate
                        total_accesses = sum(self.service_access_count[remote_ip].values())
                        if total_accesses > 0:
                            max_service = max(self.service_access_count[remote_ip].values())
                            self.same_service_rate[remote_ip] = max_service / total_accesses
                        
                        # ===== ENHANCED: Host-based features =====
                        self.dst_host_connections[remote_ip][local_ip] += 1
                        self.dst_host_srv_count[remote_ip][remote_port] += 1
                        
                        # ===== NEW: Multi-host and port pattern tracking =====
                        # Track which hosts access each service
                        self.service_hosts[remote_port]['hosts'].add(local_ip)
                        self.host_service_distribution[remote_ip][remote_port].add(local_ip)
                        
                        # Track source port patterns
                        self.src_port_history[remote_ip][local_ip].append(local_port)
                        # Keep only last 100 source ports per connection pair
                        if len(self.src_port_history[remote_ip][local_ip]) > 100:
                            self.src_port_history[remote_ip][local_ip] = self.src_port_history[remote_ip][local_ip][-100:]
                        
                        # Track outbound commands (connections to command-like ports)
                        if remote_port in self.command_ports:
                            self.outbound_commands[local_ip] += 1
                        
                        # ===== Calculate real ML features =====
                        # Count connections in last 2 seconds (for 'count' feature)
                        recent_conn_count = len([
                            c for c in self.connection_history.get(remote_ip, [])
                            if (current_time - c['time']).total_seconds() < 2
                        ])
                        
                        # Calculate error rates
                        total_conn = self.connection_success[remote_ip] + self.syn_errors[remote_ip] + self.connection_errors[remote_ip]
                        serror_rate = self.syn_errors[remote_ip] / max(total_conn, 1)
                        rerror_rate = self.connection_errors[remote_ip] / max(total_conn, 1)
                        
                        # Calculate srv_serror_rate (same service error rate)
                        srv_conn = self.service_access_count[remote_ip].get(remote_port, 0)
                        srv_serror_rate = serror_rate if srv_conn > 0 else 0.0
                        
                        # dst_host features
                        dst_host_count = sum(self.dst_host_connections[remote_ip].values())
                        dst_host_srv_count = self.dst_host_srv_count[remote_ip].get(remote_port, 0)
                        dst_host_same_srv_rate = dst_host_srv_count / max(dst_host_count, 1)
                        dst_host_diff_srv_rate = 1.0 - dst_host_same_srv_rate
                        
                        # ===== NEW: srv_diff_host_rate calculation =====
                        # % of connections to same service from different hosts
                        hosts_using_service = len(self.service_hosts.get(remote_port, {}).get('hosts', set()))
                        total_service_conns = sum(self.service_access_count[ip].get(remote_port, 0) 
                                                  for ip in self.service_access_count)
                        srv_diff_host_rate = (hosts_using_service - 1) / max(hosts_using_service, 1) if hosts_using_service > 1 else 0.0
                        
                        # ===== NEW: dst_host_same_src_port_rate calculation =====
                        # % of connections from this host using the same source port
                        src_ports_to_host = self.src_port_history.get(remote_ip, {}).get(local_ip, [])
                        if len(src_ports_to_host) > 1:
                            from collections import Counter
                            port_counts = Counter(src_ports_to_host)
                            most_common_port_count = port_counts.most_common(1)[0][1]
                            dst_host_same_src_port_rate = most_common_port_count / len(src_ports_to_host)
                        else:
                            dst_host_same_src_port_rate = 1.0
                        
                        # ===== NEW: dst_host_srv_diff_host_rate =====
                        # % of connections to this service on dst_host from different source hosts
                        hosts_to_dst_srv = len(self.host_service_distribution.get(remote_ip, {}).get(remote_port, set()))
                        dst_host_srv_diff_host_rate = (hosts_to_dst_srv - 1) / max(hosts_to_dst_srv, 1) if hosts_to_dst_srv > 1 else 0.0
                        
                        # Num outbound commands
                        num_outbound_cmds = self.outbound_commands.get(local_ip, 0)
                        
                        # Create network event for REAL connection with ML features
                        network_event = {
                            'timestamp': current_time.isoformat(),
                            'event_type': 'connection',
                            'local_addr': f"{local_ip}:{local_port}",
                            'remote_addr': f"{remote_ip}:{remote_port}",
                            'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                            'protocol_type': 1 if conn.type == socket.SOCK_STREAM else 2,
                            'status': conn.status,
                            'pid': conn.pid,
                            'src_ip': local_ip,
                            'dst_ip': remote_ip,
                            'src_port': local_port,
                            'dst_port': remote_port,
                            'is_new_connection': is_new,
                            'is_real_traffic': True,
                            
                            # ===== NEW: Real ML features =====
                            'connection_duration': connection_duration,
                            'count': recent_conn_count,  # connections to same host in window
                            'srv_count': srv_conn,  # connections to same service
                            'serror_rate': serror_rate,
                            'srv_serror_rate': srv_serror_rate,
                            'rerror_rate': rerror_rate,
                            'srv_rerror_rate': rerror_rate,  # simplified
                            'same_srv_rate': self.same_service_rate.get(remote_ip, 1.0),
                            'diff_srv_rate': 1.0 - self.same_service_rate.get(remote_ip, 1.0),
                            'dst_host_count': min(dst_host_count, 255),
                            'dst_host_srv_count': min(dst_host_srv_count, 255),
                            'dst_host_same_srv_rate': dst_host_same_srv_rate,
                            'dst_host_diff_srv_rate': dst_host_diff_srv_rate,
                            'dst_host_serror_rate': serror_rate,
                            'dst_host_srv_serror_rate': srv_serror_rate,
                            'dst_host_rerror_rate': rerror_rate,
                            'dst_host_srv_rerror_rate': rerror_rate,
                            
                            # ===== NEW: Additional multi-host features =====
                            'srv_diff_host_rate': srv_diff_host_rate,
                            'dst_host_same_src_port_rate': dst_host_same_src_port_rate,
                            'dst_host_srv_diff_host_rate': dst_host_srv_diff_host_rate,
                            'num_outbound_cmds': num_outbound_cmds,
                            
                            # Bytes (will be updated from network I/O)
                            'bytes_per_second': self.bytes_per_second.get('total', 0),
                            'packets_per_second': self.packets_per_second.get('total', 0),
                            'src_bytes': self.bytes_per_second.get('sent', 0),
                            'dst_bytes': self.bytes_per_second.get('recv', 0),
                            
                            # Port-based service detection
                            'service_type': self._get_service_type(remote_port),
                            'is_logged_in': 1 if conn.status == 'ESTABLISHED' else 0,
                        }
                        
                        # ===== NEW: Add login stats from login_rate_limiter =====
                        login_limiter = get_login_rate_limiter()
                        if login_limiter:
                            # Get login stats for both local and remote IP
                            login_stats = login_limiter.get_login_stats_for_ml(remote_ip)
                            if login_stats['num_failed_logins'] == 0:
                                # Also check local IP (for incoming attack detection)
                                login_stats = login_limiter.get_login_stats_for_ml(local_ip)
                            
                            network_event.update({
                                'num_failed_logins': login_stats['num_failed_logins'],
                                'is_guest_login': login_stats['is_guest_login'],
                                'is_host_login': login_stats['is_host_login'],
                                'su_attempted': login_stats['su_attempted'],
                                'num_root': login_stats.get('root_shell_attempted', 0),
                                'login_is_locked': login_stats['is_locked'],
                            })
                        
                        # ===== NEW: Add file operation stats =====
                        file_ops = self.file_operations.get(remote_ip, {})
                        network_event.update({
                            'num_file_creations': file_ops.get('file_creations', 0),
                            'num_access_files': file_ops.get('file_access', 0),
                            'num_shells': file_ops.get('shells_opened', 0),
                        })
                        
                        # ===== NEW: Add packet-level ML features (wrong_fragment, urgent, num_compromised) =====
                        packet_analyzer = get_packet_analyzer()
                        if packet_analyzer:
                            packet_ml_features = packet_analyzer.get_ml_features_for_connection(local_ip, remote_ip)
                            network_event.update({
                                'wrong_fragment': packet_ml_features.get('wrong_fragment', 0),
                                'urgent': packet_ml_features.get('urgent', 0),
                                'num_compromised': packet_ml_features.get('num_compromised', 0),
                            })
                        else:
                            # Default values if Scapy not available
                            network_event.update({
                                'wrong_fragment': 0,
                                'urgent': 0,
                                'num_compromised': 0,
                            })
                        
                        # Try to get process name
                        if conn.pid:
                            try:
                                proc = psutil.Process(conn.pid)
                                network_event['process_name'] = proc.name()
                                network_event['process_cmdline'] = ' '.join(proc.cmdline()[:3])
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                network_event['process_name'] = 'unknown'
                        
                        # Update connection stats
                        self.connection_stats[conn_key]['count'] += 1
                        self.connection_stats[conn_key]['last_seen'] = current_time
                        if not self.connection_stats[conn_key].get('first_seen'):
                            self.connection_stats[conn_key]['first_seen'] = current_time
                        
                        # Track connection history for pattern analysis
                        self.connection_history[remote_ip].append({
                            'time': current_time,
                            'port': remote_port,
                            'status': conn.status
                        })
                        
                        # Track ports accessed by each IP
                        self.port_access_history[remote_ip].add(remote_port)
                        
                        # Add to network data
                        self.network_data.append(network_event)
                        
                        # Check for suspicious patterns
                        self._check_connection_suspicious(network_event, remote_ip)
            
            # Track closed connections and clean up duration tracking
            for old_conn in self.previous_connections:
                if old_conn not in current_connections:
                    # Connection closed - remove from duration tracking
                    if old_conn in self.connection_start_times:
                        del self.connection_start_times[old_conn]
                    
                    closed_event = {
                        'timestamp': current_time.isoformat(),
                        'event_type': 'connection_closed',
                        'connection': old_conn,
                        'is_real_traffic': True
                    }
                    self.network_data.append(closed_event)
            
            self.previous_connections = current_connections
                    
        except Exception as e:
            logger.error(f"Error monitoring connections: {str(e)}")
    
    def _get_service_type(self, port: int) -> str:
        """Map port to service type"""
        service_map = {
            20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap', 443: 'https',
            445: 'smb', 993: 'imaps', 995: 'pop3s', 3306: 'mysql',
            3389: 'rdp', 5432: 'postgresql', 6379: 'redis', 27017: 'mongodb'
        }
        return service_map.get(port, 'other')
    
    def _monitor_network_io(self):
        """Monitor network interface I/O statistics with rate calculation"""
        try:
            current_time = datetime.now(timezone.utc)
            net_io = psutil.net_io_counters(pernic=True)
            total_io = psutil.net_io_counters(pernic=False)
            
            # Calculate rates if we have previous data
            if self.prev_net_io and self.last_io_time:
                time_diff = (current_time - self.last_io_time).total_seconds()
                if time_diff > 0:
                    # Calculate bytes per second
                    bytes_sent_diff = total_io.bytes_sent - self.prev_net_io.bytes_sent
                    bytes_recv_diff = total_io.bytes_recv - self.prev_net_io.bytes_recv
                    packets_sent_diff = total_io.packets_sent - self.prev_net_io.packets_sent
                    packets_recv_diff = total_io.packets_recv - self.prev_net_io.packets_recv
                    
                    self.bytes_per_second['sent'] = bytes_sent_diff / time_diff
                    self.bytes_per_second['recv'] = bytes_recv_diff / time_diff
                    self.bytes_per_second['total'] = (bytes_sent_diff + bytes_recv_diff) / time_diff
                    
                    self.packets_per_second['sent'] = packets_sent_diff / time_diff
                    self.packets_per_second['recv'] = packets_recv_diff / time_diff
                    self.packets_per_second['total'] = (packets_sent_diff + packets_recv_diff) / time_diff
            
            # Store current values for next calculation
            self.prev_net_io = total_io
            self.last_io_time = current_time
            self.total_bytes_sent = total_io.bytes_sent
            self.total_bytes_recv = total_io.bytes_recv
            self.total_packets_sent = total_io.packets_sent
            self.total_packets_recv = total_io.packets_recv
            
            for interface, stats in net_io.items():
                if interface != 'lo':  # Skip loopback
                    io_event = {
                        'timestamp': current_time.isoformat(),
                        'event_type': 'network_io',
                        'interface': interface,
                        'bytes_sent': stats.bytes_sent,
                        'bytes_recv': stats.bytes_recv,
                        'packets_sent': stats.packets_sent,
                        'packets_recv': stats.packets_recv,
                        'errors_in': stats.errin,
                        'errors_out': stats.errout,
                        'drops_in': stats.dropin,
                        'drops_out': stats.dropout,
                        'is_real_traffic': True,
                        # Rate data
                        'bytes_per_second': self.bytes_per_second.get('total', 0),
                        'packets_per_second': self.packets_per_second.get('total', 0),
                    }
                    # Only add if there's actual activity
                    if stats.bytes_sent > 0 or stats.bytes_recv > 0:
                        self.network_data.append(io_event)
                        
        except Exception as e:
            logger.error(f"Error monitoring network I/O: {str(e)}")
    
    def _check_connection_suspicious(self, event: Dict, remote_ip: str):
        """Check if a connection is suspicious based on patterns"""
        try:
            current_time = datetime.now(timezone.utc)
            suspicious = False
            reason = []
            
            # Check for port scan (many ports from same IP)
            ports_accessed = len(self.port_access_history.get(remote_ip, set()))
            if ports_accessed > 10:
                suspicious = True
                reason.append(f"Port scan: {ports_accessed} different ports accessed")
            
            # Check for suspicious ports
            suspicious_ports = {23, 135, 139, 445, 1433, 3306, 3389, 5900, 6379, 27017}
            if event.get('dst_port') in suspicious_ports:
                suspicious = True
                reason.append(f"Access to suspicious port: {event.get('dst_port')}")
            
            # Check for high connection rate from same IP
            recent_connections = [
                c for c in self.connection_history.get(remote_ip, [])
                if (current_time - c['time']).total_seconds() < 60
            ]
            if len(recent_connections) > 50:
                suspicious = True
                reason.append(f"High connection rate: {len(recent_connections)} connections/minute")
            
            if suspicious:
                alert = {
                    'timestamp': current_time.isoformat(),
                    'event_type': 'suspicious_connection',
                    'severity': 'HIGH' if len(reason) > 1 else 'MEDIUM',
                    'source_ip': remote_ip,
                    'destination_port': event.get('dst_port'),
                    'reasons': reason,
                    'is_real_traffic': True
                }
                self.suspicious_activities.append(alert)
                
                # Keep only recent suspicious activities
                if len(self.suspicious_activities) > 1000:
                    self.suspicious_activities = self.suspicious_activities[-500:]
                        
        except Exception as e:
            logger.error(f"Error checking connection: {str(e)}")
    
    def _monitor_processes(self):
        """Monitor system processes for suspicious activity and file operations"""
        try:
            current_time = datetime.now(timezone.utc)
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username', 'open_files', 'cmdline']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info.get('name', '').lower()
                    
                    # ===== Track shell processes =====
                    if proc_name in self.shell_processes:
                        # Get connections for this shell
                        try:
                            connections = proc.net_connections()
                            for conn in connections:
                                if conn.raddr:
                                    remote_ip = conn.raddr.ip
                                    self.file_operations[remote_ip]['shells_opened'] += 1
                                    self.file_operations[remote_ip]['last_updated'] = current_time
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    
                    # ===== Track file operations =====
                    try:
                        open_files = proc_info.get('open_files') or []
                        if len(open_files) > 0:
                            # Get network connections for this process
                            connections = proc.net_connections()
                            for conn in connections:
                                if conn.raddr:
                                    remote_ip = conn.raddr.ip
                                    self.file_operations[remote_ip]['file_access'] += len(open_files)
                                    self.file_operations[remote_ip]['last_updated'] = current_time
                                    
                                    # Check for write operations (new file creations)
                                    for f in open_files:
                                        if hasattr(f, 'mode') and 'w' in str(f.mode):
                                            self.file_operations[remote_ip]['file_creations'] += 1
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    
                    # Check for suspicious process behavior
                    if proc_info['cpu_percent'] and proc_info['cpu_percent'] > 80:
                        suspicious_event = {
                            'timestamp': current_time.isoformat(),
                            'event_type': 'high_cpu_process',
                            'pid': proc_info['pid'],
                            'process_name': proc_info['name'],
                            'cpu_percent': proc_info['cpu_percent'],
                            'memory_percent': proc_info['memory_percent'],
                            'username': proc_info.get('username', 'unknown'),
                            'severity': 'MEDIUM',
                            'is_real_traffic': True
                        }
                        self.suspicious_activities.append(suspicious_event)
                    
                    # Check for processes with many network connections
                    try:
                        connections = proc.net_connections()
                        if len(connections) > 100:
                            suspicious_event = {
                                'timestamp': current_time.isoformat(),
                                'event_type': 'high_connection_process',
                                'pid': proc_info['pid'],
                                'process_name': proc_info['name'],
                                'connection_count': len(connections),
                                'severity': 'HIGH',
                                'is_real_traffic': True
                            }
                            self.suspicious_activities.append(suspicious_event)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Cleanup old file operation tracking (keep last 10 minutes)
            cutoff = current_time - timedelta(minutes=10)
            for ip in list(self.file_operations.keys()):
                if self.file_operations[ip]['last_updated'] and self.file_operations[ip]['last_updated'] < cutoff:
                    del self.file_operations[ip]
                    
        except Exception as e:
            logger.error(f"Error monitoring processes: {str(e)}")
    
    def _analyze_connection_patterns(self):
        """Analyze connection patterns for anomalies"""
        current_time = datetime.now(timezone.utc)
        
        # Clean old connection history (keep last 5 minutes)
        for ip in list(self.connection_history.keys()):
            self.connection_history[ip] = [
                c for c in self.connection_history[ip]
                if (current_time - c['time']).total_seconds() < 300
            ]
            if not self.connection_history[ip]:
                del self.connection_history[ip]
                if ip in self.port_access_history:
                    del self.port_access_history[ip]
    
    def _get_base_network(self):
        """Get base network from target_network_range or detect automatically"""
        if self.target_network_range:
            if '/' in self.target_network_range:
                return self.target_network_range.split('/')[0].rsplit('.', 1)[0]
            else:
                return self.target_network_range.rsplit('.', 1)[0]
        
        # Try to detect local network
        try:
            addrs = psutil.net_if_addrs()
            for interface, addr_list in addrs.items():
                for addr in addr_list:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        return addr.address.rsplit('.', 1)[0]
        except:
            pass
        
        return "192.168.1"  # Default fallback
    
    def get_recent_network_data(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent REAL network data for analysis"""
        return list(self.network_data)[-limit:] if self.network_data else []
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics from REAL traffic"""
        current_time = datetime.now(timezone.utc)
        active_connections = len([conn for conn in self.connection_stats.values() 
                                if conn['last_seen'] and 
                                (current_time - conn['last_seen']).seconds < 300])
        
        # Count by status
        try:
            connections = psutil.net_connections(kind='inet')
            status_counts = defaultdict(int)
            for conn in connections:
                status_counts[conn.status] += 1
        except:
            status_counts = {}
        
        return {
            'total_connections_tracked': len(self.connection_stats),
            'active_connections': active_connections,
            'total_network_events': len(self.network_data),
            'suspicious_activities': len(self.suspicious_activities),
            'unique_remote_ips': len(self.connection_history),
            'connection_status': dict(status_counts),
            'monitoring_mode': 'REAL_TRAFFIC'
        }
    
    def get_suspicious_activities(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent suspicious activities from REAL traffic"""
        return self.suspicious_activities[-limit:] if self.suspicious_activities else []
    
    def analyze_traffic_patterns(self) -> Dict[str, Any]:
        """Analyze REAL traffic patterns for anomalies"""
        if not self.network_data:
            return {'message': 'No network data available - waiting for traffic'}
        
        recent_data = list(self.network_data)[-1000:]
        
        # Analyze patterns from REAL traffic
        src_ips = defaultdict(int)
        dst_ips = defaultdict(int)
        dst_ports = defaultdict(int)
        protocols = defaultdict(int)
        processes = defaultdict(int)
        high_volume_sources = []
        
        for event in recent_data:
            if event.get('event_type') in ['connection', 'packet']:
                src_ip = event.get('src_ip', 'unknown')
                dst_ip = event.get('dst_ip', 'unknown')
                src_ips[src_ip] += 1
                dst_ips[dst_ip] += 1
                dst_ports[event.get('dst_port', 0)] += 1
                protocols[event.get('protocol', 'unknown')] += 1
                if event.get('process_name'):
                    processes[event.get('process_name')] += 1
        
        # Identify high volume sources (potential threats)
        for ip, count in src_ips.items():
            if count > 50:
                high_volume_sources.append({
                    'src_ip': ip,
                    'event_count': count,
                    'severity': 'HIGH' if count > 100 else 'MEDIUM'
                })
        
        return {
            'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
            'total_events_analyzed': len(recent_data),
            'unique_source_ips': len(src_ips),
            'unique_destination_ips': len(dst_ips),
            'top_source_ips': dict(sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_destination_ips': dict(sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
            'most_active_ports': dict(sorted(dst_ports.items(), key=lambda x: x[1], reverse=True)[:10]),
            'protocol_distribution': dict(protocols),
            'top_processes': dict(sorted(processes.items(), key=lambda x: x[1], reverse=True)[:10]),
            'high_volume_sources': high_volume_sources,
            'potential_threats': len(high_volume_sources),
            'data_source': 'REAL_NETWORK_TRAFFIC'
        }

# Global network monitor instance
network_monitor = NetworkMonitor()

async def start_network_monitoring_for_range(network_range: str, monitoring_type: str = "full"):
    """Start network monitoring for a specific network range"""
    logger.info(f"Starting network monitoring for range: {network_range}, type: {monitoring_type}")
    
    # Store the network range in the monitor for targeted monitoring
    network_monitor.target_network_range = network_range
    network_monitor.monitoring_type = monitoring_type
    
    # Start the global monitoring
    network_monitor.start_monitoring()
    
    logger.info(f"✅ Network monitoring active for {network_range}")

def start_network_monitoring():
    """Start the global network monitor"""
    network_monitor.start_monitoring()

def stop_network_monitoring():
    """Stop the global network monitor"""
    network_monitor.stop_monitoring()

def get_network_monitor() -> NetworkMonitor:
    """Get the global network monitor instance"""
    return network_monitor