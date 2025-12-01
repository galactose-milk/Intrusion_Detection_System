# backend/app/network_monitor.py
"""
Real Network Monitor for Intrusion Detection System
Monitors actual network connections and system activities - NO SIMULATIONS
"""
import asyncio
import psutil
import socket
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import logging
from collections import defaultdict, deque
import time
import threading
import struct

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
        """Monitor REAL active network connections"""
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
                        
                        # Create network event for REAL connection
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
                            'is_real_traffic': True
                        }
                        
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
            
            # Track closed connections
            for old_conn in self.previous_connections:
                if old_conn not in current_connections:
                    # Connection closed
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
    
    def _monitor_network_io(self):
        """Monitor network interface I/O statistics"""
        try:
            current_time = datetime.now(timezone.utc)
            net_io = psutil.net_io_counters(pernic=True)
            
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
                        'is_real_traffic': True
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
        """Monitor system processes for suspicious activity"""
        try:
            current_time = datetime.now(timezone.utc)
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username']):
                try:
                    proc_info = proc.info
                    
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