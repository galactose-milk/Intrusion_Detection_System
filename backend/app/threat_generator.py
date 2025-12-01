# backend/app/threat_generator.py
"""
Real Threat Generator for IDS Testing
Creates ACTUAL resource-consuming processes to test detection and response

WARNING: This tool creates real processes that consume CPU/RAM.
Use responsibly and only for testing purposes.
"""

import os
import sys
import time
import signal
import psutil
import threading
import subprocess
import multiprocessing
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
import logging
import json
import hashlib
import tempfile

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ThreatProcess:
    """Represents a running threat test process"""
    threat_id: int  # Internal threat ID for management
    pid: int
    threat_type: str
    name: str
    start_time: datetime
    target_cpu: float = 0.0
    target_ram_mb: int = 0
    description: str = ""
    is_active: bool = True
    intensity: str = "medium"
    process: Optional[multiprocessing.Process] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'threat_id': self.threat_id,
            'pid': self.pid,
            'threat_type': self.threat_type,
            'name': self.name,
            'start_time': self.start_time.isoformat(),
            'target_cpu': self.target_cpu,
            'target_ram_mb': self.target_ram_mb,
            'description': self.description,
            'is_active': self.is_active,
            'intensity': self.intensity
        }


class CPUStressWorker:
    """Worker that consumes CPU - simulates crypto miner"""
    
    @staticmethod
    def stress_cpu(target_percent: float, duration: int, stop_event: threading.Event):
        """
        Consume CPU at approximately target_percent for duration seconds.
        Uses busy-wait with sleep to achieve target CPU usage.
        """
        import math
        
        start_time = time.time()
        
        while not stop_event.is_set() and (time.time() - start_time) < duration:
            # Calculate work/sleep ratio for target CPU
            work_time = target_percent / 100.0
            sleep_time = 1.0 - work_time
            
            # Do intensive work
            work_start = time.time()
            while (time.time() - work_start) < work_time * 0.1:  # 100ms cycles
                # CPU intensive calculations
                _ = [math.sqrt(i) * math.sin(i) for i in range(10000)]
            
            # Sleep to reduce CPU
            if sleep_time > 0:
                time.sleep(sleep_time * 0.1)


class MemoryStressWorker:
    """Worker that consumes RAM - simulates memory leak or data loading"""
    
    @staticmethod
    def stress_memory(target_mb: int, duration: int, stop_event: threading.Event):
        """
        Allocate and hold target_mb of memory for duration seconds.
        """
        # Allocate memory in chunks
        chunk_size = 10 * 1024 * 1024  # 10 MB chunks
        chunks = []
        allocated_mb = 0
        
        try:
            while allocated_mb < target_mb and not stop_event.is_set():
                # Allocate a chunk of memory and fill it to prevent optimization
                chunk = bytearray(chunk_size)
                for i in range(0, len(chunk), 4096):
                    chunk[i] = i % 256
                chunks.append(chunk)
                allocated_mb += 10
                time.sleep(0.1)  # Gradual allocation
            
            logger.info(f"Allocated {allocated_mb} MB of memory")
            
            # Hold memory until stopped or duration expires
            start_time = time.time()
            while not stop_event.is_set() and (time.time() - start_time) < duration:
                time.sleep(1)
                # Touch memory periodically to prevent swapping
                for chunk in chunks:
                    _ = chunk[0]
                    
        finally:
            # Release memory
            chunks.clear()
            logger.info("Memory released")


class NetworkStressWorker:
    """Worker that generates network traffic - simulates data exfiltration"""
    
    @staticmethod
    def stress_network(target_host: str, duration: int, stop_event: threading.Event):
        """
        Generate network connections to simulate suspicious activity.
        """
        import socket
        
        start_time = time.time()
        connection_count = 0
        
        while not stop_event.is_set() and (time.time() - start_time) < duration:
            try:
                # Try to connect to common ports (will likely fail, but generates traffic)
                for port in [80, 443, 22, 8080, 3389]:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        sock.connect((target_host, port))
                        sock.close()
                        connection_count += 1
                    except:
                        pass
                time.sleep(0.5)
            except Exception as e:
                logger.debug(f"Network stress error: {e}")
                
        logger.info(f"Made {connection_count} connection attempts")


class DiskStressWorker:
    """Worker that generates disk I/O - simulates ransomware or data theft"""
    
    @staticmethod
    def stress_disk(target_mb: int, duration: int, stop_event: threading.Event):
        """
        Generate disk I/O to simulate suspicious file activity.
        """
        temp_dir = tempfile.mkdtemp(prefix="ids_test_")
        files_created = []
        
        try:
            start_time = time.time()
            bytes_written = 0
            target_bytes = target_mb * 1024 * 1024
            
            while not stop_event.is_set() and (time.time() - start_time) < duration:
                if bytes_written < target_bytes:
                    # Create a file with random data
                    filename = os.path.join(temp_dir, f"test_{len(files_created)}.dat")
                    chunk = os.urandom(1024 * 1024)  # 1 MB
                    with open(filename, 'wb') as f:
                        f.write(chunk)
                    files_created.append(filename)
                    bytes_written += len(chunk)
                else:
                    # Read files back (simulate data access)
                    for f in files_created:
                        if stop_event.is_set():
                            break
                        try:
                            with open(f, 'rb') as file:
                                _ = file.read()
                        except:
                            pass
                    time.sleep(1)
                    
            logger.info(f"Wrote {bytes_written / (1024*1024):.1f} MB to disk")
            
        finally:
            # Cleanup
            for f in files_created:
                try:
                    os.remove(f)
                except:
                    pass
            try:
                os.rmdir(temp_dir)
            except:
                pass


class ThreatGenerator:
    """
    Main class to generate real threat-like processes for IDS testing.
    These are REAL processes that consume actual system resources.
    """
    
    def __init__(self):
        self.active_threats: Dict[int, ThreatProcess] = {}
        self.stop_events: Dict[int, threading.Event] = {}
        self.threads: Dict[int, List[threading.Thread]] = {}
        self.threat_counter = 0
        
    def generate_crypto_miner(self, 
                              target_cpu_percent: float = 60.0,
                              duration_seconds: int = 300,
                              num_threads: int = None) -> ThreatProcess:
        """
        Generate a process that behaves like a crypto miner.
        Uses multiple threads to achieve target CPU usage.
        """
        if num_threads is None:
            num_threads = max(1, multiprocessing.cpu_count() // 2)
        
        # Calculate per-thread CPU target
        per_thread_cpu = target_cpu_percent / num_threads
        
        self.threat_counter += 1
        threat_id = self.threat_counter
        stop_event = threading.Event()
        
        threads = []
        for i in range(num_threads):
            t = threading.Thread(
                target=CPUStressWorker.stress_cpu,
                args=(per_thread_cpu, duration_seconds, stop_event),
                name=f"CryptoMiner-{threat_id}-{i}",
                daemon=True
            )
            t.start()
            threads.append(t)
        
        threat = ThreatProcess(
            threat_id=threat_id,
            pid=os.getpid(),  # Same process, different threads
            threat_type="crypto_miner",
            name=f"CryptoMiner-{threat_id}",
            start_time=datetime.now(timezone.utc),
            target_cpu=target_cpu_percent,
            description=f"Simulated crypto miner using {num_threads} threads at {target_cpu_percent}% CPU"
        )
        
        self.active_threats[threat_id] = threat
        self.stop_events[threat_id] = stop_event
        self.threads[threat_id] = threads
        
        logger.info(f"Started crypto miner simulation: {threat.name}")
        return threat
    
    def generate_memory_leak(self,
                             target_ram_mb: int = 500,
                             duration_seconds: int = 300) -> ThreatProcess:
        """
        Generate a process that consumes memory like a memory leak or malware loading data.
        """
        self.threat_counter += 1
        threat_id = self.threat_counter
        stop_event = threading.Event()
        
        t = threading.Thread(
            target=MemoryStressWorker.stress_memory,
            args=(target_ram_mb, duration_seconds, stop_event),
            name=f"MemoryLeak-{threat_id}",
            daemon=True
        )
        t.start()
        
        threat = ThreatProcess(
            threat_id=threat_id,
            pid=os.getpid(),
            threat_type="memory_leak",
            name=f"MemoryLeak-{threat_id}",
            start_time=datetime.now(timezone.utc),
            target_ram_mb=target_ram_mb,
            description=f"Simulated memory leak consuming {target_ram_mb} MB"
        )
        
        self.active_threats[threat_id] = threat
        self.stop_events[threat_id] = stop_event
        self.threads[threat_id] = [t]
        
        logger.info(f"Started memory leak simulation: {threat.name}")
        return threat
    
    def generate_data_exfiltration(self,
                                   target_host: str = "8.8.8.8",
                                   duration_seconds: int = 300) -> ThreatProcess:
        """
        Generate network activity that looks like data exfiltration.
        """
        self.threat_counter += 1
        threat_id = self.threat_counter
        stop_event = threading.Event()
        
        t = threading.Thread(
            target=NetworkStressWorker.stress_network,
            args=(target_host, duration_seconds, stop_event),
            name=f"DataExfil-{threat_id}",
            daemon=True
        )
        t.start()
        
        threat = ThreatProcess(
            threat_id=threat_id,
            pid=os.getpid(),
            threat_type="data_exfiltration",
            name=f"DataExfil-{threat_id}",
            start_time=datetime.now(timezone.utc),
            description=f"Simulated data exfiltration to {target_host}"
        )
        
        self.active_threats[threat_id] = threat
        self.stop_events[threat_id] = stop_event
        self.threads[threat_id] = [t]
        
        logger.info(f"Started data exfiltration simulation: {threat.name}")
        return threat
    
    def generate_ransomware_activity(self,
                                     target_disk_mb: int = 100,
                                     duration_seconds: int = 300) -> ThreatProcess:
        """
        Generate disk I/O that looks like ransomware encrypting files.
        """
        self.threat_counter += 1
        threat_id = self.threat_counter
        stop_event = threading.Event()
        
        t = threading.Thread(
            target=DiskStressWorker.stress_disk,
            args=(target_disk_mb, duration_seconds, stop_event),
            name=f"Ransomware-{threat_id}",
            daemon=True
        )
        t.start()
        
        threat = ThreatProcess(
            threat_id=threat_id,
            pid=os.getpid(),
            threat_type="ransomware",
            name=f"Ransomware-{threat_id}",
            start_time=datetime.now(timezone.utc),
            description=f"Simulated ransomware disk activity ({target_disk_mb} MB)"
        )
        
        self.active_threats[threat_id] = threat
        self.stop_events[threat_id] = stop_event
        self.threads[threat_id] = [t]
        
        logger.info(f"Started ransomware simulation: {threat.name}")
        return threat
    
    def generate_combined_attack(self,
                                 cpu_percent: float = 50.0,
                                 ram_mb: int = 300,
                                 duration_seconds: int = 300) -> List[ThreatProcess]:
        """
        Generate a combined attack that uses CPU, RAM, and network.
        This simulates a sophisticated attack like a crypto miner with C2 communication.
        """
        threats = []
        
        # CPU stress
        threats.append(self.generate_crypto_miner(
            target_cpu_percent=cpu_percent,
            duration_seconds=duration_seconds
        ))
        
        # Memory stress
        threats.append(self.generate_memory_leak(
            target_ram_mb=ram_mb,
            duration_seconds=duration_seconds
        ))
        
        # Network stress
        threats.append(self.generate_data_exfiltration(
            duration_seconds=duration_seconds
        ))
        
        logger.info(f"Started combined attack simulation with {len(threats)} components")
        return threats
    
    def stop_threat(self, threat_id: int) -> bool:
        """Stop a specific threat by ID"""
        if threat_id in self.stop_events:
            self.stop_events[threat_id].set()
            
            # Wait for threads to stop
            if threat_id in self.threads:
                for t in self.threads[threat_id]:
                    t.join(timeout=5)
                del self.threads[threat_id]
            
            if threat_id in self.active_threats:
                self.active_threats[threat_id].is_active = False
                
            del self.stop_events[threat_id]
            logger.info(f"Stopped threat {threat_id}")
            return True
        return False
    
    def stop_all_threats(self) -> int:
        """Stop all running threats"""
        count = 0
        for threat_id in list(self.stop_events.keys()):
            if self.stop_threat(threat_id):
                count += 1
        logger.info(f"Stopped {count} threats")
        return count
    
    def get_active_threats(self) -> List[Dict[str, Any]]:
        """Get list of all active threats"""
        return [t.to_dict() for t in self.active_threats.values() if t.is_active]
    
    def get_threat_status(self) -> Dict[str, Any]:
        """Get overall threat generator status"""
        return {
            'total_threats_created': self.threat_counter,
            'active_threats': len([t for t in self.active_threats.values() if t.is_active]),
            'threats': self.get_active_threats()
        }
    
    def start_threat(self, threat_type: str, intensity: str = "medium", duration: int = 30) -> Optional[ThreatProcess]:
        """
        Start a threat of the specified type with given intensity.
        This is the main API method for generating threats.
        
        Args:
            threat_type: CPU_MINER, MEMORY_HOG, DISK_ABUSE, NETWORK_FLOOD, CRYPTO_MINER, DATA_EXFILTRATION
            intensity: low, medium, high
            duration: Duration in seconds
            
        Returns:
            ThreatProcess object with threat details
        """
        # Intensity mappings
        intensity_config = {
            "low": {"cpu": 20, "ram": 200, "disk": 50},
            "medium": {"cpu": 50, "ram": 500, "disk": 200},
            "high": {"cpu": 80, "ram": 1000, "disk": 500}
        }
        
        config = intensity_config.get(intensity.lower(), intensity_config["medium"])
        
        threat_map = {
            "CPU_MINER": lambda: self.generate_crypto_miner(
                target_cpu_percent=config["cpu"], 
                duration_seconds=duration
            ),
            "MEMORY_HOG": lambda: self.generate_memory_leak(
                target_ram_mb=config["ram"], 
                duration_seconds=duration
            ),
            "DISK_ABUSE": lambda: self.generate_ransomware_activity(
                target_disk_mb=config["disk"], 
                duration_seconds=duration
            ),
            "NETWORK_FLOOD": lambda: self.generate_data_exfiltration(
                duration_seconds=duration
            ),
            "CRYPTO_MINER": lambda: self.generate_crypto_miner(
                target_cpu_percent=config["cpu"], 
                duration_seconds=duration
            ),
            "DATA_EXFILTRATION": lambda: self.generate_data_exfiltration(
                duration_seconds=duration
            )
        }
        
        generator = threat_map.get(threat_type.upper())
        if generator:
            threat = generator()
            threat.intensity = intensity
            return threat
        else:
            logger.error(f"Unknown threat type: {threat_type}")
            return None
    
    def get_active_threats(self) -> List['ThreatProcess']:
        """Get list of all active threat process objects"""
        return [t for t in self.active_threats.values() if t.is_active]


# Global instance
threat_generator = ThreatGenerator()


def get_threat_generator() -> ThreatGenerator:
    return threat_generator
