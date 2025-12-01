# backend/app/process_quarantine.py
"""
Process Quarantine and Response System for IDS
Detects malicious processes and takes action (kill, suspend, alert)

This is a REAL security response system that can:
- Monitor process resource usage
- Detect anomalous behavior
- Quarantine (suspend) or kill malicious processes
- Log all actions for forensics
"""

import os
import signal
import psutil
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ResponseAction(Enum):
    """Actions that can be taken on a process"""
    ALERT = "alert"           # Just alert, don't take action
    SUSPEND = "suspend"       # Pause the process (SIGSTOP)
    RESUME = "resume"         # Resume a suspended process (SIGCONT)
    TERMINATE = "terminate"   # Graceful kill (SIGTERM)
    KILL = "kill"             # Force kill (SIGKILL)
    QUARANTINE = "quarantine" # Suspend + isolate


class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ProcessThreatInfo:
    """Information about a potentially malicious process"""
    pid: int
    name: str
    cmdline: str
    username: str
    cpu_percent: float
    memory_percent: float
    memory_mb: float
    connections: int
    open_files: int
    create_time: datetime
    threat_level: ThreatLevel
    threat_reasons: List[str]
    detection_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    action_taken: Optional[ResponseAction] = None
    is_quarantined: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'pid': self.pid,
            'name': self.name,
            'cmdline': self.cmdline,
            'username': self.username,
            'cpu_percent': self.cpu_percent,
            'memory_percent': self.memory_percent,
            'memory_mb': self.memory_mb,
            'connections': self.connections,
            'open_files': self.open_files,
            'create_time': self.create_time.isoformat() if self.create_time else None,
            'threat_level': self.threat_level.value,
            'threat_reasons': self.threat_reasons,
            'detection_time': self.detection_time.isoformat(),
            'action_taken': self.action_taken.value if self.action_taken else None,
            'is_quarantined': self.is_quarantined
        }


@dataclass
class DetectionRule:
    """Rule for detecting malicious process behavior"""
    name: str
    description: str
    enabled: bool = True
    threat_level: ThreatLevel = ThreatLevel.MEDIUM
    auto_action: Optional[ResponseAction] = None
    
    # Thresholds
    cpu_threshold: Optional[float] = None          # CPU % threshold
    memory_threshold: Optional[float] = None       # Memory % threshold
    memory_mb_threshold: Optional[float] = None    # Memory MB threshold
    connection_threshold: Optional[int] = None     # Network connections threshold
    open_files_threshold: Optional[int] = None     # Open files threshold
    
    # Process name patterns to match (or exclude)
    process_name_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    
    # Time-based detection
    sustained_seconds: int = 30  # How long condition must be true


class ProcessQuarantineSystem:
    """
    Real-time process monitoring and quarantine system.
    Detects and responds to malicious process behavior.
    """
    
    # System/critical processes that should never be touched
    PROTECTED_PROCESSES = {
        'systemd', 'init', 'kernel', 'kthreadd', 'ksoftirqd',
        'python', 'python3', 'uvicorn', 'node', 'npm',  # Our own processes
        'Xorg', 'gnome-shell', 'kwin', 'pulseaudio', 'pipewire',
        'sshd', 'NetworkManager', 'dbus-daemon', 'polkitd',
        'bash', 'zsh', 'sh', 'fish',  # Shells
    }
    
    # Default detection rules
    DEFAULT_RULES = [
        DetectionRule(
            name="High CPU Usage",
            description="Process using excessive CPU for extended period",
            cpu_threshold=80.0,
            sustained_seconds=60,
            threat_level=ThreatLevel.HIGH,
            auto_action=ResponseAction.ALERT
        ),
        DetectionRule(
            name="Crypto Miner Detection",
            description="Process showing crypto miner behavior (sustained high CPU)",
            cpu_threshold=60.0,
            sustained_seconds=120,
            threat_level=ThreatLevel.CRITICAL,
            auto_action=ResponseAction.SUSPEND,
            exclude_patterns=['python', 'node', 'java', 'chrome', 'firefox']
        ),
        DetectionRule(
            name="Memory Exhaustion",
            description="Process consuming excessive memory",
            memory_mb_threshold=2000,  # 2 GB
            threat_level=ThreatLevel.HIGH,
            auto_action=ResponseAction.ALERT
        ),
        DetectionRule(
            name="Suspicious Network Activity",
            description="Process with unusually high number of connections",
            connection_threshold=100,
            threat_level=ThreatLevel.MEDIUM,
            auto_action=ResponseAction.ALERT
        ),
        DetectionRule(
            name="File System Abuse",
            description="Process with unusually high number of open files",
            open_files_threshold=500,
            threat_level=ThreatLevel.MEDIUM,
            auto_action=ResponseAction.ALERT
        ),
        DetectionRule(
            name="Resource Hog",
            description="Process using both high CPU and memory",
            cpu_threshold=50.0,
            memory_mb_threshold=1000,
            threat_level=ThreatLevel.HIGH,
            auto_action=ResponseAction.SUSPEND
        ),
    ]
    
    def __init__(self):
        self.rules: List[DetectionRule] = self.DEFAULT_RULES.copy()
        self.detected_threats: Dict[int, ProcessThreatInfo] = {}
        self.quarantined_pids: set = set()
        self.action_log: deque = deque(maxlen=1000)
        self.process_history: Dict[int, deque] = defaultdict(lambda: deque(maxlen=60))
        
        self.is_monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.auto_response_enabled = False
        
        # Callbacks for alerts
        self.alert_callbacks: List[Callable] = []
        
    def add_rule(self, rule: DetectionRule):
        """Add a custom detection rule"""
        self.rules.append(rule)
        logger.info(f"Added detection rule: {rule.name}")
        
    def add_alert_callback(self, callback: Callable):
        """Add callback to be called when threat is detected"""
        self.alert_callbacks.append(callback)
        
    def start_monitoring(self, interval: float = 5.0, auto_response: bool = False):
        """Start real-time process monitoring"""
        if self.is_monitoring:
            logger.warning("Monitoring already running")
            return
            
        self.is_monitoring = True
        self.auto_response_enabled = auto_response
        
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
        logger.info(f"Started process monitoring (interval: {interval}s, auto_response: {auto_response})")
        
    def stop_monitoring(self):
        """Stop process monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)
        logger.info("Stopped process monitoring")
        
    def _monitor_loop(self, interval: float):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                self._scan_processes()
                time.sleep(interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(interval)
                
    def _scan_processes(self):
        """Scan all processes for threats"""
        current_time = datetime.now(timezone.utc)
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 
                                         'memory_percent', 'memory_info', 'connections',
                                         'open_files', 'cmdline', 'create_time']):
            try:
                info = proc.info
                pid = info['pid']
                name = info['name'] or 'unknown'
                
                # Skip protected processes
                if name in self.PROTECTED_PROCESSES:
                    continue
                    
                # Skip our own process
                if pid == os.getpid():
                    continue
                
                # Get detailed info
                cpu_percent = info['cpu_percent'] or 0
                mem_percent = info['memory_percent'] or 0
                mem_mb = (info['memory_info'].rss / (1024 * 1024)) if info.get('memory_info') else 0
                connections = len(info.get('connections') or [])
                open_files = len(info.get('open_files') or [])
                cmdline = ' '.join(info.get('cmdline') or [])[:200]
                
                # Record history
                self.process_history[pid].append({
                    'time': current_time,
                    'cpu': cpu_percent,
                    'mem': mem_mb
                })
                
                # Check against rules
                for rule in self.rules:
                    if not rule.enabled:
                        continue
                        
                    if self._check_rule(rule, pid, name, cpu_percent, mem_percent, 
                                       mem_mb, connections, open_files, cmdline):
                        # Threat detected!
                        threat = self._create_threat_info(
                            proc, rule, cpu_percent, mem_percent, mem_mb,
                            connections, open_files, cmdline
                        )
                        
                        self._handle_threat(threat, rule)
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
    def _check_rule(self, rule: DetectionRule, pid: int, name: str,
                   cpu: float, mem_pct: float, mem_mb: float,
                   conns: int, files: int, cmdline: str) -> bool:
        """Check if a process matches a detection rule"""
        
        # Check exclusions first
        for pattern in rule.exclude_patterns:
            if pattern.lower() in name.lower() or pattern.lower() in cmdline.lower():
                return False
        
        # Check name patterns if specified
        if rule.process_name_patterns:
            matches_pattern = any(
                p.lower() in name.lower() or p.lower() in cmdline.lower()
                for p in rule.process_name_patterns
            )
            if not matches_pattern:
                return False
        
        conditions_met = []
        
        # Check CPU threshold
        if rule.cpu_threshold is not None:
            if cpu >= rule.cpu_threshold:
                # Check if sustained
                if self._is_sustained(pid, 'cpu', rule.cpu_threshold, rule.sustained_seconds):
                    conditions_met.append('cpu')
                    
        # Check memory threshold
        if rule.memory_threshold is not None:
            if mem_pct >= rule.memory_threshold:
                conditions_met.append('memory_percent')
                
        if rule.memory_mb_threshold is not None:
            if mem_mb >= rule.memory_mb_threshold:
                conditions_met.append('memory_mb')
                
        # Check connection threshold
        if rule.connection_threshold is not None:
            if conns >= rule.connection_threshold:
                conditions_met.append('connections')
                
        # Check open files threshold
        if rule.open_files_threshold is not None:
            if files >= rule.open_files_threshold:
                conditions_met.append('open_files')
                
        # Rule matches if any threshold is exceeded
        # For rules with multiple thresholds, all must be exceeded
        required_conditions = sum([
            rule.cpu_threshold is not None,
            rule.memory_threshold is not None or rule.memory_mb_threshold is not None,
            rule.connection_threshold is not None,
            rule.open_files_threshold is not None
        ])
        
        return len(conditions_met) >= required_conditions and required_conditions > 0
        
    def _is_sustained(self, pid: int, metric: str, threshold: float, seconds: int) -> bool:
        """Check if a condition has been sustained for specified duration"""
        history = self.process_history.get(pid, [])
        if not history:
            return False
            
        now = datetime.now(timezone.utc)
        sustained_count = 0
        
        for entry in history:
            age = (now - entry['time']).total_seconds()
            if age <= seconds:
                if metric == 'cpu' and entry['cpu'] >= threshold:
                    sustained_count += 1
                elif metric == 'mem' and entry['mem'] >= threshold:
                    sustained_count += 1
                    
        # Need at least half the entries to exceed threshold
        return sustained_count >= len(history) / 2
        
    def _create_threat_info(self, proc, rule: DetectionRule, 
                           cpu: float, mem_pct: float, mem_mb: float,
                           conns: int, files: int, cmdline: str) -> ProcessThreatInfo:
        """Create threat info object"""
        info = proc.info
        
        reasons = []
        if rule.cpu_threshold and cpu >= rule.cpu_threshold:
            reasons.append(f"CPU usage {cpu:.1f}% >= {rule.cpu_threshold}%")
        if rule.memory_mb_threshold and mem_mb >= rule.memory_mb_threshold:
            reasons.append(f"Memory {mem_mb:.1f}MB >= {rule.memory_mb_threshold}MB")
        if rule.connection_threshold and conns >= rule.connection_threshold:
            reasons.append(f"Connections {conns} >= {rule.connection_threshold}")
            
        return ProcessThreatInfo(
            pid=info['pid'],
            name=info['name'],
            cmdline=cmdline,
            username=info.get('username', 'unknown'),
            cpu_percent=cpu,
            memory_percent=mem_pct,
            memory_mb=mem_mb,
            connections=conns,
            open_files=files,
            create_time=datetime.fromtimestamp(info.get('create_time', 0), tz=timezone.utc),
            threat_level=rule.threat_level,
            threat_reasons=reasons
        )
        
    def _handle_threat(self, threat: ProcessThreatInfo, rule: DetectionRule):
        """Handle a detected threat"""
        # Only process if not already handled
        if threat.pid in self.detected_threats:
            existing = self.detected_threats[threat.pid]
            if existing.action_taken:
                return
                
        self.detected_threats[threat.pid] = threat
        
        # Log detection
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event': 'threat_detected',
            'pid': threat.pid,
            'name': threat.name,
            'rule': rule.name,
            'threat_level': threat.threat_level.value,
            'reasons': threat.threat_reasons
        }
        self.action_log.append(log_entry)
        logger.warning(f"THREAT DETECTED: {threat.name} (PID {threat.pid}) - {rule.name}")
        
        # Notify callbacks
        for callback in self.alert_callbacks:
            try:
                callback(threat)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
        
        # Take auto action if enabled
        if self.auto_response_enabled and rule.auto_action:
            self.take_action(threat.pid, rule.auto_action)
            
    def take_action(self, pid: int, action: ResponseAction) -> Dict[str, Any]:
        """Take action on a process"""
        result = {
            'pid': pid,
            'action': action.value,
            'success': False,
            'message': '',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        try:
            proc = psutil.Process(pid)
            
            # Safety check
            if proc.name() in self.PROTECTED_PROCESSES:
                result['message'] = f"Cannot take action on protected process: {proc.name()}"
                return result
                
            if action == ResponseAction.ALERT:
                result['success'] = True
                result['message'] = "Alert logged"
                
            elif action == ResponseAction.SUSPEND:
                proc.suspend()
                self.quarantined_pids.add(pid)
                if pid in self.detected_threats:
                    self.detected_threats[pid].is_quarantined = True
                    self.detected_threats[pid].action_taken = action
                result['success'] = True
                result['message'] = f"Process {pid} suspended (quarantined)"
                
            elif action == ResponseAction.RESUME:
                proc.resume()
                self.quarantined_pids.discard(pid)
                if pid in self.detected_threats:
                    self.detected_threats[pid].is_quarantined = False
                result['success'] = True
                result['message'] = f"Process {pid} resumed"
                
            elif action == ResponseAction.TERMINATE:
                proc.terminate()
                proc.wait(timeout=5)
                self.quarantined_pids.discard(pid)
                if pid in self.detected_threats:
                    self.detected_threats[pid].action_taken = action
                result['success'] = True
                result['message'] = f"Process {pid} terminated"
                
            elif action == ResponseAction.KILL:
                proc.kill()
                self.quarantined_pids.discard(pid)
                if pid in self.detected_threats:
                    self.detected_threats[pid].action_taken = action
                result['success'] = True
                result['message'] = f"Process {pid} killed"
                
            elif action == ResponseAction.QUARANTINE:
                proc.suspend()
                self.quarantined_pids.add(pid)
                if pid in self.detected_threats:
                    self.detected_threats[pid].is_quarantined = True
                    self.detected_threats[pid].action_taken = action
                result['success'] = True
                result['message'] = f"Process {pid} quarantined (suspended)"
                
        except psutil.NoSuchProcess:
            result['message'] = f"Process {pid} no longer exists"
        except psutil.AccessDenied:
            result['message'] = f"Access denied to process {pid} - need root privileges"
        except Exception as e:
            result['message'] = f"Error: {str(e)}"
            
        # Log action
        self.action_log.append(result)
        logger.info(f"Action taken: {result}")
        
        return result
        
    def get_detected_threats(self) -> List[Dict[str, Any]]:
        """Get all detected threats"""
        return [t.to_dict() for t in self.detected_threats.values()]
        
    def get_quarantined_processes(self) -> List[Dict[str, Any]]:
        """Get currently quarantined processes"""
        quarantined = []
        for pid in self.quarantined_pids:
            if pid in self.detected_threats:
                quarantined.append(self.detected_threats[pid].to_dict())
        return quarantined
        
    def get_action_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent action log"""
        return list(self.action_log)[-limit:]
        
    def get_status(self) -> Dict[str, Any]:
        """Get quarantine system status"""
        return {
            'is_monitoring': self.is_monitoring,
            'auto_response_enabled': self.auto_response_enabled,
            'rules_count': len(self.rules),
            'detected_threats': len(self.detected_threats),
            'quarantined_count': len(self.quarantined_pids),
            'action_log_size': len(self.action_log)
        }


# Global instance
quarantine_system = ProcessQuarantineSystem()


def get_quarantine_system() -> ProcessQuarantineSystem:
    return quarantine_system
