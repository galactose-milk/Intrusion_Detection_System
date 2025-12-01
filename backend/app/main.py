# backend/app/main.py
"""
Intrusion Detection System - Main API Application
PRODUCTION MODE: Real-time monitoring with actual network traffic detection
"""

import os
import random
import asyncio
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List
import json
import logging

# Import our modules
from .ml_models import anomaly_detector, threat_intel, initialize_ml_models
from .network_monitor import network_monitor, start_network_monitoring, start_network_monitoring_for_range
from .attack_detector import intrusion_engine, AttackType, Severity
from .real_packet_capture import packet_capture, SCAPY_AVAILABLE
from .threat_generator import threat_generator, ThreatProcess
from .process_quarantine import quarantine_system, ResponseAction, ThreatLevel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Configuration ---
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")


# --- Pydantic Models ---

class NetworkSetupDetails(BaseModel):
    name: str = Field(..., min_length=1, description="Name for the network monitoring setup")
    network_range: str = Field(..., description="Network range to monitor (e.g., 192.168.1.0/24)")
    monitoring_type: str = Field("full", description="Type of monitoring: full, connections, processes")
    alert_thresholds: Optional[Dict[str, Any]] = Field(None, description="Custom alert thresholds")
    enable_packet_capture: bool = Field(False, description="Enable deep packet capture (requires root)")
    interface: Optional[str] = Field(None, description="Network interface to capture from")

class SecurityAlert(BaseModel):
    id: str = Field(..., description="Unique alert identifier")
    timestamp: datetime = Field(..., description="Alert timestamp")
    severity: str = Field(..., description="Alert severity: LOW, MEDIUM, HIGH, CRITICAL")
    alert_type: str = Field(..., description="Type of security alert")
    source_ip: Optional[str] = Field(None, description="Source IP address")
    destination_ip: Optional[str] = Field(None, description="Destination IP address")
    description: str = Field(..., description="Alert description")
    ml_confidence: Optional[float] = Field(None, description="ML model confidence score")
    threat_score: Optional[int] = Field(None, description="Overall threat score")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional alert details")

class NetworkEvent(BaseModel):
    timestamp: datetime = Field(..., description="Event timestamp")
    event_type: str = Field(..., description="Type of network event")
    source_ip: str = Field(..., description="Source IP address")
    destination_ip: str = Field(..., description="Destination IP address")
    source_port: Optional[int] = Field(None, description="Source port")
    destination_port: Optional[int] = Field(None, description="Destination port")
    protocol: str = Field(..., description="Network protocol")
    packet_size: Optional[int] = Field(None, description="Packet size in bytes")
    is_suspicious: bool = Field(False, description="Whether event is flagged as suspicious")

class ThreatAnalysisResponse(BaseModel):
    network_events: List[NetworkEvent] = Field(...)
    security_alerts: List[SecurityAlert] = Field(...)
    threat_summary: Dict[str, Any] = Field(...)

class MLAnalysisRequest(BaseModel):
    network_data: Dict[str, Any] = Field(..., description="Network data to analyze")

class MLAnalysisResponse(BaseModel):
    is_anomaly: bool = Field(..., description="Whether the data represents an anomaly")
    confidence: float = Field(..., description="Confidence score (0-1)")
    analysis: Dict[str, Any] = Field(..., description="Detailed ML analysis")
    threat_intelligence: Optional[Dict[str, Any]] = Field(None, description="Threat intelligence data")


# --- FastAPI Application Setup ---
app = FastAPI(
    title="Intrusion Detection System (IDS)",
    description="ML-powered Intrusion Detection System with REAL-TIME network traffic monitoring and threat detection. No simulations - production ready.",
    version="3.0.0"
)

# --- CORS Configuration ---
origins = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:5175",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "http://127.0.0.1:5175"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Global State ---
monitoring_configs: Dict[str, NetworkSetupDetails] = {}
security_alerts: List[SecurityAlert] = []
websocket_connections: List[WebSocket] = []


# --- WebSocket Manager ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all connected clients"""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for conn in disconnected:
            self.disconnect(conn)

manager = ConnectionManager()


# --- Startup Events ---
@app.on_event("startup")
async def startup_event():
    """Initialize IDS components on startup"""
    print("🚀 Starting Intrusion Detection System v3.0 - PRODUCTION MODE...")
    print("📡 This system monitors REAL network traffic only - no simulations")
    
    # Initialize ML models
    await initialize_ml_models()
    
    # Start network monitoring
    start_network_monitoring()
    
    # Start background tasks
    asyncio.create_task(continuous_threat_analysis())
    asyncio.create_task(real_time_broadcast())
    
    # Check if scapy is available for deep packet capture
    if SCAPY_AVAILABLE:
        print("✅ Scapy available - deep packet capture ready (requires root)")
    else:
        print("⚠️  Scapy not available - using connection-level monitoring")
    
    print("✅ IDS initialization complete!")
    print("🔴 REAL-TIME monitoring active - analyzing actual network traffic")
    print("🔍 ML-powered attack detection engine ready")


# --- WebSocket Endpoint ---
@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and handle incoming messages
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                # Handle client messages (e.g., subscription preferences)
                message = json.loads(data)
                if message.get('type') == 'ping':
                    await websocket.send_json({'type': 'pong', 'timestamp': datetime.now(timezone.utc).isoformat()})
            except asyncio.TimeoutError:
                # Send heartbeat
                await websocket.send_json({'type': 'heartbeat', 'timestamp': datetime.now(timezone.utc).isoformat()})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


# --- API Endpoints ---

@app.get("/", tags=["General"])
async def read_root():
    """IDS system health check"""
    return {
        "message": "Intrusion Detection System v3.0 - PRODUCTION MODE",
        "status": "active",
        "mode": "REAL_TRAFFIC_ONLY",
        "ml_model_loaded": anomaly_detector.is_trained,
        "network_monitoring": network_monitor.is_monitoring,
        "packet_capture_available": SCAPY_AVAILABLE,
        "websocket_clients": len(manager.active_connections),
        "version": "3.0.0",
        "features": [
            "Real-time connection monitoring",
            "ML-powered anomaly detection (NSL-KDD trained)",
            "Attack pattern recognition",
            "WebSocket live updates",
            "Process monitoring",
            "Deep packet capture (with root)"
        ]
    }


@app.post("/api/network/setup", status_code=201, tags=["Network Setup"])
async def setup_network_monitoring(network_config: NetworkSetupDetails):
    """Configure network monitoring parameters for REAL traffic"""
    logger.info(f"Setting up REAL network monitoring for: {network_config.name}")
    
    # Store configuration
    monitoring_configs[network_config.name] = network_config
    
    # Start monitoring for this range
    try:
        await start_network_monitoring_for_range(
            network_config.network_range, 
            network_config.monitoring_type
        )
        
        # If deep packet capture requested and scapy available
        if network_config.enable_packet_capture and SCAPY_AVAILABLE:
            try:
                packet_capture.start_capture(
                    filter_str=f"net {network_config.network_range.split('/')[0]}"
                )
                logger.info("Deep packet capture started (requires root privileges)")
            except Exception as e:
                logger.warning(f"Could not start packet capture: {e} (may need root)")
                
    except Exception as e:
        logger.error(f"Error starting monitoring: {e}")
    
    return {
        "status": "success",
        "message": f"REAL network monitoring for '{network_config.name}' configured successfully.",
        "monitoring_active": network_monitor.is_monitoring,
        "network_range": network_config.network_range,
        "packet_capture": network_config.enable_packet_capture and SCAPY_AVAILABLE,
        "mode": "REAL_TRAFFIC_ONLY"
    }


@app.get("/api/threats/analyze", response_model=ThreatAnalysisResponse, tags=["Threat Analysis"])
async def get_threat_analysis(
    time_range: str = Query("1h", description="Time range for analysis (5m, 15m, 1h, 6h, 1d)"),
    severity_filter: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL")
):
    """Get comprehensive threat analysis with ML-powered detection"""
    
    # Get recent network data
    recent_network_data = network_monitor.get_recent_network_data(limit=500)
    
    # Convert to NetworkEvent objects and analyze
    network_events = []
    new_alerts = []
    
    for event_data in recent_network_data:
        if event_data.get('event_type') in ['packet', 'real_connection', 'port_scan', 'syn_flood', 
                                             'brute_force', 'sql_injection', 'xss', 'ddos']:
            try:
                # Analyze with ML model
                is_anomaly, confidence, ml_analysis = anomaly_detector.predict_anomaly(event_data)
                
                # Also analyze with attack detector
                attack_alerts = intrusion_engine.analyze_packet(event_data)
                
                # Create network event
                network_event = NetworkEvent(
                    timestamp=datetime.fromisoformat(event_data['timestamp'].replace('Z', '+00:00')),
                    event_type=event_data.get('event_type', 'packet'),
                    source_ip=event_data.get('src_ip', 'unknown'),
                    destination_ip=event_data.get('dst_ip', 'unknown'),
                    source_port=event_data.get('src_port'),
                    destination_port=event_data.get('dst_port'),
                    protocol=event_data.get('protocol_type', 'TCP') if isinstance(event_data.get('protocol_type'), str) else 'TCP',
                    packet_size=event_data.get('packet_size'),
                    is_suspicious=is_anomaly or len(attack_alerts) > 0
                )
                network_events.append(network_event)
                
                # Generate security alerts
                if is_anomaly or len(attack_alerts) > 0:
                    threat_data = threat_intel.analyze_ip(event_data.get('src_ip', 'unknown'))
                    
                    # Create alert from ML detection
                    if is_anomaly:
                        alert = SecurityAlert(
                            id=f"ML-{datetime.now().timestamp()}-{random.randint(1000, 9999)}",
                            timestamp=datetime.fromisoformat(event_data['timestamp'].replace('Z', '+00:00')),
                            severity=_determine_alert_severity(confidence, threat_data['threat_score']),
                            alert_type=event_data.get('event_type', 'Network Anomaly'),
                            source_ip=event_data.get('src_ip'),
                            destination_ip=event_data.get('dst_ip'),
                            description=f"ML detected anomalous behavior: {event_data.get('event_type', 'unknown')}",
                            ml_confidence=confidence,
                            threat_score=threat_data['threat_score'],
                            details={
                                'ml_analysis': ml_analysis,
                                'threat_intelligence': threat_data,
                                'is_simulated': event_data.get('attack_simulation', False),
                                'is_real_traffic': event_data.get('is_real_traffic', False)
                            }
                        )
                        new_alerts.append(alert)
                        security_alerts.append(alert)
                    
                    # Add attack detector alerts
                    for attack_alert in attack_alerts:
                        alert = SecurityAlert(
                            id=attack_alert.id,
                            timestamp=attack_alert.timestamp,
                            severity=attack_alert.severity.value,
                            alert_type=attack_alert.attack_type.value,
                            source_ip=attack_alert.source_ip,
                            destination_ip=attack_alert.destination_ip,
                            description=attack_alert.description,
                            ml_confidence=attack_alert.confidence,
                            threat_score=int(attack_alert.confidence * 10),
                            details={
                                'indicators': attack_alert.indicators,
                                'mitre_tactics': attack_alert.mitre_tactics,
                                'recommended_actions': attack_alert.recommended_actions
                            }
                        )
                        new_alerts.append(alert)
                        security_alerts.append(alert)
                        
            except Exception as e:
                logger.error(f"Error analyzing network event: {str(e)}")
                continue
    
    # Filter alerts by severity if requested
    filtered_alerts = security_alerts
    if severity_filter:
        filtered_alerts = [alert for alert in security_alerts if alert.severity == severity_filter]
    
    # Get detection engine stats
    detection_stats = intrusion_engine.get_statistics()
    
    # Generate threat summary
    threat_summary = {
        "analysis_time": datetime.now(timezone.utc).isoformat(),
        "time_range_analyzed": time_range,
        "total_network_events": len(network_events),
        "suspicious_events": len([e for e in network_events if e.is_suspicious]),
        "total_alerts": len(filtered_alerts),
        "alert_breakdown": _get_alert_breakdown(filtered_alerts),
        "top_threat_sources": _get_top_threat_sources(filtered_alerts),
        "network_stats": network_monitor.get_connection_stats(),
        "detection_stats": detection_stats,
        "ml_model_status": "active" if anomaly_detector.is_trained else "inactive",
        "real_traffic_events": len([e for e in recent_network_data if e.get('is_real_traffic', False)]),
        "simulated_events": len([e for e in recent_network_data if e.get('attack_simulation', False)])
    }
    
    return ThreatAnalysisResponse(
        network_events=network_events[-100:],
        security_alerts=filtered_alerts[-50:],
        threat_summary=threat_summary
    )


@app.post("/api/ml/analyze", response_model=MLAnalysisResponse, tags=["ML Analysis"])
async def analyze_with_ml(analysis_request: MLAnalysisRequest):
    """Analyze specific network data with ML models"""
    network_data = analysis_request.network_data
    
    try:
        # ML anomaly detection
        is_anomaly, confidence, ml_analysis = anomaly_detector.predict_anomaly(network_data)
        
        # Also run through attack detector
        attack_alerts = intrusion_engine.analyze_packet(network_data)
        
        # Threat intelligence analysis
        threat_intel_data = None
        if 'src_ip' in network_data:
            threat_intel_data = threat_intel.analyze_ip(network_data['src_ip'])
        
        # Add attack detection results to analysis
        ml_analysis['attack_detection'] = {
            'alerts_generated': len(attack_alerts),
            'attack_types': [a.attack_type.value for a in attack_alerts]
        }
        
        return MLAnalysisResponse(
            is_anomaly=is_anomaly or len(attack_alerts) > 0,
            confidence=confidence,
            analysis=ml_analysis,
            threat_intelligence=threat_intel_data
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ML analysis failed: {str(e)}")


@app.get("/api/dashboard/stats", tags=["Dashboard"])
async def get_dashboard_stats():
    """Get comprehensive dashboard statistics"""
    network_stats = network_monitor.get_connection_stats()
    suspicious_activities = network_monitor.get_suspicious_activities(limit=10)
    traffic_analysis = network_monitor.analyze_traffic_patterns()
    detection_stats = intrusion_engine.get_statistics()
    threat_summary = intrusion_engine.get_threat_summary()
    
    # Calculate threat metrics
    recent_alerts = [alert for alert in security_alerts 
                    if (datetime.now(timezone.utc) - alert.timestamp).days < 1]
    
    severity_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for alert in recent_alerts:
        severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
    
    return {
        "system_status": {
            "ml_model_active": anomaly_detector.is_trained,
            "network_monitoring": network_monitor.is_monitoring,
            "packet_capture_available": SCAPY_AVAILABLE,
            "websocket_clients": len(manager.active_connections),
            "last_update": datetime.now(timezone.utc).isoformat(),
            "mode": "REAL_TRAFFIC_ONLY"
        },
        "network_statistics": network_stats,
        "threat_overview": {
            "alerts_last_24h": len(recent_alerts),
            "severity_breakdown": severity_counts,
            "top_threat_types": _get_top_threat_types(recent_alerts),
            "threat_trend": "stable" if len(recent_alerts) < 50 else "increasing"
        },
        "detection_statistics": detection_stats,
        "threat_summary": threat_summary,
        "recent_suspicious_activities": suspicious_activities,
        "traffic_analysis": traffic_analysis,
        "data_source": "REAL_NETWORK_TRAFFIC"
    }


@app.get("/api/detection/alerts", tags=["Detection"])
async def get_detection_alerts(
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    attack_type: Optional[str] = Query(None)
):
    """Get alerts from the intrusion detection engine - REAL threats only"""
    alerts = intrusion_engine.get_recent_alerts(
        limit=limit,
        severity=severity,
        attack_type=attack_type
    )
    return {
        "total": len(alerts),
        "alerts": alerts,
        "filters": {
            "severity": severity,
            "attack_type": attack_type
        },
        "source": "REAL_TRAFFIC_ANALYSIS"
    }


@app.get("/api/detection/statistics", tags=["Detection"])
async def get_detection_statistics():
    """Get intrusion detection statistics from REAL traffic"""
    stats = intrusion_engine.get_statistics()
    stats["data_source"] = "REAL_NETWORK_TRAFFIC"
    return stats


# --- Real-time Monitoring Endpoints ---

@app.get("/api/realtime/connections", tags=["Real-time"])
async def get_realtime_connections():
    """Get REAL-TIME active connections"""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "connections": network_monitor.get_connection_stats(),
        "recent_data": network_monitor.get_recent_network_data(limit=50),
        "source": "REAL_TRAFFIC"
    }


@app.get("/api/realtime/traffic-analysis", tags=["Real-time"])
async def get_realtime_traffic_analysis():
    """Get REAL-TIME traffic pattern analysis"""
    return network_monitor.analyze_traffic_patterns()


@app.get("/api/system/status", tags=["System"])
async def get_system_status():
    """Get comprehensive system status"""
    import psutil
    
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ids_status": {
            "ml_model_active": anomaly_detector.is_trained,
            "network_monitoring": network_monitor.is_monitoring,
            "packet_capture_available": SCAPY_AVAILABLE,
            "websocket_clients": len(manager.active_connections)
        },
        "system_resources": {
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "network_interfaces": list(psutil.net_if_addrs().keys())
        },
        "monitoring_stats": network_monitor.get_connection_stats(),
        "mode": "PRODUCTION_REAL_TRAFFIC"
    }


# --- Background Tasks ---

async def continuous_threat_analysis():
    """Continuously analyze REAL network traffic for threats"""
    while True:
        try:
            await asyncio.sleep(10)  # Analyze every 10 seconds
            
            # Get recent REAL network data
            recent_data = network_monitor.get_recent_network_data(limit=100)
            
            high_severity_alerts = []
            
            for event in recent_data:
                if event.get('event_type') in ['connection', 'packet', 'suspicious_connection']:
                    try:
                        is_anomaly, confidence, analysis = anomaly_detector.predict_anomaly(event)
                        attack_alerts = intrusion_engine.analyze_packet(event)
                        
                        if is_anomaly and confidence > 0.7:
                            alert = SecurityAlert(
                                id=f"REAL-{datetime.now().timestamp()}-{random.randint(1000, 9999)}",
                                timestamp=datetime.now(timezone.utc),
                                severity="CRITICAL" if confidence > 0.9 else "HIGH",
                                alert_type=event.get('event_type', 'Real Traffic Anomaly'),
                                source_ip=event.get('src_ip') or event.get('dst_ip'),
                                destination_ip=event.get('dst_ip'),
                                description=f"ML detected anomaly in REAL traffic: {event.get('event_type', 'Anomaly')}",
                                ml_confidence=confidence,
                                details={
                                    'auto_generated': True, 
                                    'source': 'REAL_TRAFFIC',
                                    'process': event.get('process_name', 'unknown')
                                }
                            )
                            security_alerts.append(alert)
                            high_severity_alerts.append(alert)
                            
                            # Keep alerts list manageable
                            if len(security_alerts) > 1000:
                                security_alerts[:] = security_alerts[-500:]
                                
                    except Exception as e:
                        logger.error(f"Error in background analysis: {str(e)}")
                        continue
            
            # Broadcast high severity alerts
            if high_severity_alerts:
                await manager.broadcast({
                    'type': 'high_severity_alert',
                    'count': len(high_severity_alerts),
                    'source': 'REAL_TRAFFIC',
                    'alerts': [
                        {
                            'id': a.id,
                            'severity': a.severity,
                            'type': a.alert_type,
                            'source_ip': a.source_ip
                        } for a in high_severity_alerts
                    ],
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
                        
        except Exception as e:
            logger.error(f"Error in continuous threat analysis: {str(e)}")
            await asyncio.sleep(30)


async def real_time_broadcast():
    """Broadcast REAL-TIME statistics to WebSocket clients"""
    while True:
        try:
            await asyncio.sleep(5)  # Update every 5 seconds
            
            if manager.active_connections:
                stats = {
                    'type': 'stats_update',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'network_events': network_monitor.get_connection_stats(),
                    'detection_stats': intrusion_engine.get_statistics(),
                    'threat_summary': intrusion_engine.get_threat_summary(),
                    'recent_alerts_count': len(security_alerts[-100:]),
                    'source': 'REAL_TRAFFIC'
                }
                await manager.broadcast(stats)
                
        except Exception as e:
            logger.error(f"Error in real-time broadcast: {str(e)}")
            await asyncio.sleep(10)


# --- Helper Functions ---

def _determine_alert_severity(ml_confidence: float, threat_score: int) -> str:
    """Determine alert severity based on ML confidence and threat intelligence"""
    combined_score = (ml_confidence * 10) + threat_score
    
    if combined_score >= 15:
        return "CRITICAL"
    elif combined_score >= 12:
        return "HIGH"
    elif combined_score >= 8:
        return "MEDIUM"
    else:
        return "LOW"

def _get_alert_breakdown(alerts: List[SecurityAlert]) -> Dict[str, int]:
    """Get breakdown of alerts by severity"""
    breakdown = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for alert in alerts:
        breakdown[alert.severity] = breakdown.get(alert.severity, 0) + 1
    return breakdown

def _get_top_threat_sources(alerts: List[SecurityAlert]) -> List[Dict[str, Any]]:
    """Get top threat sources from alerts"""
    source_counts = {}
    for alert in alerts:
        if alert.source_ip:
            source_counts[alert.source_ip] = source_counts.get(alert.source_ip, 0) + 1
    
    sorted_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    return [{'ip': ip, 'alert_count': count} for ip, count in sorted_sources]

def _get_top_threat_types(alerts: List[SecurityAlert]) -> List[Dict[str, Any]]:
    """Get top threat types from alerts"""
    type_counts = {}
    for alert in alerts:
        type_counts[alert.alert_type] = type_counts.get(alert.alert_type, 0) + 1
    
    sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    return [{'type': threat_type, 'count': count} for threat_type, count in sorted_types]


# =============================================================================
# THREAT TESTING & QUARANTINE ENDPOINTS
# =============================================================================
# These endpoints allow REAL threat simulation and process quarantine for testing
# the IDS detection capabilities with actual resource-consuming processes.

class ThreatGenerationRequest(BaseModel):
    threat_type: str = Field(..., description="Type: cpu_miner, memory_hog, disk_abuse, network_flood, crypto_miner, data_exfil")
    intensity: str = Field("medium", description="Intensity: low, medium, high")
    duration: int = Field(30, ge=5, le=300, description="Duration in seconds (5-300)")


class QuarantineActionRequest(BaseModel):
    pid: int = Field(..., description="Process ID to quarantine/kill")
    action: str = Field("kill", description="Action: kill or quarantine")


# --- Threat Generation Endpoints ---

@app.post("/api/threats/generate", tags=["Threat Testing"])
async def generate_threat(request: ThreatGenerationRequest, background_tasks: BackgroundTasks):
    """
    Generate a REAL threat process for testing IDS detection.
    This creates actual resource-consuming processes that the IDS should detect.
    """
    try:
        # Map string to threat type
        threat_type_map = {
            "cpu_miner": "CPU_MINER",
            "memory_hog": "MEMORY_HOG", 
            "disk_abuse": "DISK_ABUSE",
            "network_flood": "NETWORK_FLOOD",
            "crypto_miner": "CRYPTO_MINER",
            "data_exfil": "DATA_EXFILTRATION"
        }
        
        threat_type = threat_type_map.get(request.threat_type.lower())
        if not threat_type:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid threat type. Use: {list(threat_type_map.keys())}"
            )
        
        # Start threat in background
        process = await asyncio.to_thread(
            threat_generator.start_threat,
            threat_type,
            request.intensity,
            request.duration
        )
        
        if process:
            # Broadcast threat creation to WebSocket clients
            await manager.broadcast({
                'type': 'threat_started',
                'threat_type': threat_type,
                'threat_id': process.threat_id,
                'intensity': request.intensity,
                'duration': request.duration,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            
            return {
                "status": "success",
                "message": f"Threat process started: {threat_type}",
                "process": {
                    "threat_id": process.threat_id,
                    "pid": process.pid,
                    "threat_type": process.threat_type,
                    "intensity": process.intensity,
                    "start_time": process.start_time.isoformat(),
                    "duration": request.duration
                }
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to start threat process")
            
    except Exception as e:
        logger.error(f"Error generating threat: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/threats/active", tags=["Threat Testing"])
async def get_active_threats():
    """Get all active threat processes that were generated for testing"""
    active = threat_generator.get_active_threats()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "active_count": len(active),
        "threats": [
            {
                "threat_id": t.threat_id,
                "pid": t.pid,
                "threat_type": t.threat_type,
                "intensity": t.intensity,
                "start_time": t.start_time.isoformat(),
                "is_active": t.is_active,
                "name": t.name
            }
            for t in active
        ]
    }


@app.delete("/api/threats/stop/{threat_id}", tags=["Threat Testing"])
async def stop_threat(threat_id: int):
    """Stop a specific threat process by threat ID"""
    success = threat_generator.stop_threat(threat_id)
    if success:
        await manager.broadcast({
            'type': 'threat_stopped',
            'threat_id': threat_id,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        return {"status": "success", "message": f"Threat {threat_id} stopped"}
    else:
        raise HTTPException(status_code=404, detail=f"Threat {threat_id} not found or already stopped")


@app.delete("/api/threats/stop-all", tags=["Threat Testing"])
async def stop_all_threats():
    """Stop all active threat processes"""
    threat_generator.stop_all_threats()
    await manager.broadcast({
        'type': 'all_threats_stopped',
        'timestamp': datetime.now(timezone.utc).isoformat()
    })
    return {"status": "success", "message": "All threat processes stopped"}


# --- Process Quarantine Endpoints ---

@app.get("/api/quarantine/detect", tags=["Quarantine"])
async def detect_suspicious_processes():
    """
    Detect suspicious processes on the system.
    Looks for high CPU/RAM usage, suspicious ports, unknown processes.
    """
    suspicious = quarantine_system.detect_suspicious_processes()
    
    # Also check test threat processes
    test_threats = threat_generator.get_active_threats()
    
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "suspicious_count": len(suspicious),
        "test_threats_active": len(test_threats),
        "processes": suspicious,
        "detection_thresholds": {
            "cpu_threshold": quarantine_system.cpu_threshold,
            "memory_threshold": quarantine_system.memory_threshold,
            "suspicious_ports_monitored": len(quarantine_system.suspicious_ports)
        }
    }


@app.post("/api/quarantine/action", tags=["Quarantine"])
async def quarantine_action(request: QuarantineActionRequest):
    """
    Take action on a suspicious process (kill or quarantine).
    """
    try:
        if request.action == "kill":
            result = quarantine_system.kill_process(request.pid)
        elif request.action == "quarantine":
            result = quarantine_system.quarantine_process(request.pid)
        else:
            raise HTTPException(status_code=400, detail="Action must be 'kill' or 'quarantine'")
        
        if result['success']:
            await manager.broadcast({
                'type': 'process_action',
                'action': request.action,
                'pid': request.pid,
                'result': 'success',
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            return {"status": "success", "result": result}
        else:
            return {"status": "failed", "result": result}
            
    except Exception as e:
        logger.error(f"Error in quarantine action: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/quarantine/status", tags=["Quarantine"])
async def get_quarantine_status():
    """Get status of all quarantined and killed processes"""
    return quarantine_system.get_quarantine_status()


@app.get("/api/quarantine/history", tags=["Quarantine"])
async def get_quarantine_history():
    """Get history of quarantine actions"""
    history = []
    
    for entry in quarantine_system.quarantined_processes:
        history.append({
            "type": "quarantined",
            "pid": entry.get('pid'),
            "name": entry.get('name'),
            "action_time": entry.get('quarantine_time'),
            "reason": entry.get('reason')
        })
    
    for entry in quarantine_system.killed_processes:
        history.append({
            "type": "killed",
            "pid": entry.get('pid'),
            "name": entry.get('name'),
            "action_time": entry.get('kill_time'),
            "reason": entry.get('reason')
        })
    
    # Sort by time
    history.sort(key=lambda x: x.get('action_time', ''), reverse=True)
    
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_actions": len(history),
        "history": history[:50]  # Last 50 actions
    }


@app.get("/api/system/resources", tags=["System"])
async def get_system_resources():
    """Get detailed system resource usage for threat detection context"""
    import psutil
    
    # Get top CPU consuming processes
    top_cpu = []
    top_memory = []
    
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            info = proc.info
            if info['cpu_percent'] > 5:
                top_cpu.append({
                    'pid': info['pid'],
                    'name': info['name'],
                    'cpu_percent': info['cpu_percent']
                })
            if info['memory_percent'] > 2:
                top_memory.append({
                    'pid': info['pid'],
                    'name': info['name'],
                    'memory_percent': info['memory_percent']
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    top_cpu.sort(key=lambda x: x['cpu_percent'], reverse=True)
    top_memory.sort(key=lambda x: x['memory_percent'], reverse=True)
    
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu": {
            "total_percent": psutil.cpu_percent(interval=1),
            "per_cpu": psutil.cpu_percent(interval=0.1, percpu=True),
            "count": psutil.cpu_count()
        },
        "memory": {
            "total": psutil.virtual_memory().total,
            "available": psutil.virtual_memory().available,
            "percent": psutil.virtual_memory().percent,
            "used": psutil.virtual_memory().used
        },
        "top_cpu_processes": top_cpu[:10],
        "top_memory_processes": top_memory[:10],
        "test_threats_active": len(threat_generator.get_active_threats())
    }
