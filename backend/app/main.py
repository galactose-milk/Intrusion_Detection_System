# backend/app/main.py
"""
Intrusion Detection System - Main API Application
PRODUCTION MODE: Real-time monitoring with actual network traffic detection
"""

import os
import random
import asyncio
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks, WebSocket, WebSocketDisconnect, Request, Response, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
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
from .ip_quarantine import ip_quarantine, BlockAction as IPBlockAction
from .auth import (
    user_store, login_user, verify_token, get_current_user, get_current_user_optional,
    require_role, UserCreate, UserLogin, TokenResponse, UserResponse, login_rate_limiter
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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
# Allow all origins for network-wide access (attacks from other machines)
# In production, you would restrict this to specific IPs
origins = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:5175",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "http://127.0.0.1:5175",
    "*"  # Allow all origins for network attack testing
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for testing
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- IP Quarantine Middleware ---
class IPQuarantineMiddleware(BaseHTTPMiddleware):
    """
    Middleware to detect and block attacking IPs.
    Records every request and checks for attack patterns.
    """
    
    # Endpoints to exclude from rate limiting (health checks, etc.)
    EXCLUDED_ENDPOINTS = {'/health', '/docs', '/openapi.json', '/redoc'}
    
    async def dispatch(self, request: Request, call_next):
        # Get client IP
        client_ip = self._get_client_ip(request)
        endpoint = request.url.path
        
        # Skip excluded endpoints
        if endpoint in self.EXCLUDED_ENDPOINTS:
            return await call_next(request)
        
        # Record request and check for attacks
        detection_result = ip_quarantine.record_request(client_ip, endpoint)
        
        # If blocked, return 429 Too Many Requests
        if detection_result.get('blocked'):
            return Response(
                content=json.dumps({
                    'error': 'IP Blocked',
                    'reason': detection_result.get('reason', 'Attack detected'),
                    'unblock_time': detection_result.get('unblock_time'),
                    'message': 'Your IP has been temporarily blocked due to suspicious activity'
                }),
                status_code=429,
                media_type='application/json'
            )
        
        # Process the request
        response = await call_next(request)
        
        # Record the response status for failed request tracking
        if response.status_code >= 400:
            ip_quarantine.record_request(client_ip, endpoint, response.status_code)
        
        # Add security headers
        response.headers['X-Request-Rate'] = str(int(ip_quarantine.ip_stats.get(client_ip, {}).requests_per_minute if hasattr(ip_quarantine.ip_stats.get(client_ip, {}), 'requests_per_minute') else 0))
        
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request, handling proxies"""
        # Check for forwarded headers (reverse proxy)
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            # Take the first IP (original client)
            return forwarded_for.split(',')[0].strip()
        
        # Check X-Real-IP
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        # Fall back to direct client
        if request.client:
            return request.client.host
        
        return '0.0.0.0'


# Add the IP quarantine middleware
app.add_middleware(IPQuarantineMiddleware)

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
    
    # Set up IP quarantine alert callback for WebSocket broadcasting
    async def ip_attack_alert_callback(alert):
        """Broadcast IP attack alerts to WebSocket clients"""
        try:
            await manager.broadcast({
                'type': 'ip_attack_detected',
                'alert': alert.to_dict(),
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        except Exception as e:
            logger.error(f"Error broadcasting IP attack alert: {e}")
    
    # We need a sync wrapper for the async callback
    def sync_alert_wrapper(alert):
        asyncio.create_task(ip_attack_alert_callback(alert))
    
    ip_quarantine.add_alert_callback(sync_alert_wrapper)
    
    # Start background tasks
    asyncio.create_task(continuous_threat_analysis())
    asyncio.create_task(real_time_broadcast())
    asyncio.create_task(ip_quarantine.auto_cleanup_task())
    
    # Check if scapy is available for deep packet capture
    if SCAPY_AVAILABLE:
        print("✅ Scapy available - deep packet capture ready (requires root)")
    else:
        print("⚠️  Scapy not available - using connection-level monitoring")
    
    print("✅ IDS initialization complete!")
    print("🔴 REAL-TIME monitoring active - analyzing actual network traffic")
    print("🔍 ML-powered attack detection engine ready")
    print("🛡️  IP Quarantine system active - detecting and blocking attacking IPs")


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
    
    # Add IP quarantine alerts to security_alerts
    ip_alerts = ip_quarantine.get_recent_alerts(limit=100)
    for ip_alert in ip_alerts:
        try:
            # Map attack type to severity
            severity_map = {
                'dos_flood': 'CRITICAL',
                'ddos_flood': 'CRITICAL', 
                'rate_limit': 'HIGH',
                'endpoint_scan': 'HIGH',
                'brute_force': 'HIGH',
                'suspicious': 'MEDIUM'
            }
            severity = severity_map.get(ip_alert.get('attack_type', ''), 'MEDIUM')
            
            alert = SecurityAlert(
                id=f"IP-{ip_alert.get('timestamp', datetime.now().isoformat())}-{ip_alert.get('ip', 'unknown')[:8]}",
                timestamp=datetime.fromisoformat(ip_alert.get('timestamp', datetime.now().isoformat()).replace('Z', '+00:00')) if isinstance(ip_alert.get('timestamp'), str) else datetime.now(timezone.utc),
                severity=severity,
                alert_type=f"IP_{ip_alert.get('attack_type', 'unknown').upper()}",
                source_ip=ip_alert.get('ip'),
                destination_ip="IDS Server",
                description=ip_alert.get('message', 'IP-based attack detected'),
                ml_confidence=0.95,
                threat_score=ip_alert.get('threat_score', 8),
                details={
                    'action': ip_alert.get('action'),
                    'requests_per_minute': ip_alert.get('requests_per_minute'),
                    'total_requests': ip_alert.get('total_requests')
                }
            )
            security_alerts.append(alert)
        except Exception as e:
            logger.error(f"Error converting IP alert: {e}")
    
    # Also add suspicious activities from network monitor as alerts
    suspicious_activities = network_monitor.get_suspicious_activities(limit=50)
    for activity in suspicious_activities:
        try:
            activity_severity = activity.get('severity', 'MEDIUM')
            alert = SecurityAlert(
                id=f"NET-{activity.get('timestamp', datetime.now().isoformat())[:19].replace(':', '-')}",
                timestamp=datetime.fromisoformat(activity.get('timestamp', datetime.now().isoformat()).replace('Z', '+00:00')) if isinstance(activity.get('timestamp'), str) else datetime.now(timezone.utc),
                severity=activity_severity,
                alert_type=activity.get('event_type', 'suspicious_activity').upper(),
                source_ip=activity.get('source_ip', 'unknown'),
                destination_ip=f"port:{activity.get('destination_port', 'unknown')}",
                description="; ".join(activity.get('reasons', ['Suspicious network activity detected'])),
                ml_confidence=0.85,
                threat_score=8 if activity_severity == 'HIGH' else 5,
                details={
                    'is_real_traffic': activity.get('is_real_traffic', True),
                    'destination_port': activity.get('destination_port')
                }
            )
            # Avoid duplicates
            if not any(a.source_ip == alert.source_ip and a.alert_type == alert.alert_type 
                      and abs((a.timestamp - alert.timestamp).total_seconds()) < 60 
                      for a in security_alerts):
                security_alerts.append(alert)
        except Exception as e:
            logger.error(f"Error converting suspicious activity: {e}")
    
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
    
    # Also include IP quarantine alerts
    ip_alerts = ip_quarantine.get_recent_alerts(limit=50)
    for ip_alert in ip_alerts:
        severity_map = {
            'dos_flood': 'CRITICAL',
            'ddos_flood': 'CRITICAL', 
            'rate_limit': 'HIGH',
            'endpoint_scan': 'HIGH',
            'brute_force': 'HIGH',
            'suspicious': 'MEDIUM'
        }
        alert_severity = severity_map.get(ip_alert.get('attack_type', ''), 'MEDIUM')
        
        # Apply severity filter if specified
        if severity and alert_severity != severity:
            continue
            
        alerts.append({
            'id': f"IP-{ip_alert.get('ip', 'unknown')[:8]}-{len(alerts)}",
            'timestamp': ip_alert.get('timestamp', datetime.now(timezone.utc).isoformat()),
            'attack_type': f"IP_{ip_alert.get('attack_type', 'unknown').upper()}",
            'severity': alert_severity,
            'source_ip': ip_alert.get('ip'),
            'destination_ip': 'IDS Server',
            'description': ip_alert.get('message', 'IP-based attack detected'),
            'indicators': [
                f"Action: {ip_alert.get('action', 'detected')}",
                f"Requests/min: {ip_alert.get('requests_per_minute', 'N/A')}"
            ],
            'confidence': 0.95,
            'mitre_tactics': ['TA0040 - Impact', 'TA0042 - Resource Development'],
            'recommended_actions': [
                f"IP {ip_alert.get('ip')} has been automatically blocked",
                'Monitor for continued attack attempts',
                'Review firewall rules'
            ]
        })
    
    # Also include suspicious activities from network monitor
    suspicious_activities = network_monitor.get_suspicious_activities(limit=50)
    for activity in suspicious_activities:
        activity_severity = activity.get('severity', 'MEDIUM')
        
        # Apply severity filter if specified
        if severity and activity_severity != severity:
            continue
        
        alerts.append({
            'id': f"NET-{activity.get('timestamp', '')[:19].replace(':', '-')}-{len(alerts)}",
            'timestamp': activity.get('timestamp', datetime.now(timezone.utc).isoformat()),
            'attack_type': activity.get('event_type', 'SUSPICIOUS_ACTIVITY').upper(),
            'severity': activity_severity,
            'source_ip': activity.get('source_ip', 'unknown'),
            'destination_ip': f"port:{activity.get('destination_port', 'unknown')}",
            'description': "; ".join(activity.get('reasons', ['Suspicious network activity detected'])),
            'indicators': activity.get('reasons', []),
            'confidence': 0.85,
            'mitre_tactics': ['TA0043 - Reconnaissance', 'TA0007 - Discovery'],
            'recommended_actions': [
                'Review network traffic patterns',
                'Check for unauthorized access attempts',
                'Enable enhanced logging'
            ]
        })
    
    # Also include login security alerts (brute force, credential stuffing)
    login_alerts = login_rate_limiter.get_recent_alerts(limit=50)
    for login_alert in login_alerts:
        alert_severity = login_alert.get('severity', 'MEDIUM')
        
        # Apply severity filter if specified
        if severity and alert_severity != severity:
            continue
        
        # Map login alert types to readable names
        alert_type_map = {
            'brute_force_detected': 'LOGIN_BRUTE_FORCE',
            'credential_stuffing_detected': 'CREDENTIAL_STUFFING',
            'login_failures_warning': 'LOGIN_FAILURES',
            'login_success_after_failures': 'SUSPICIOUS_LOGIN'
        }
        
        alerts.append({
            'id': f"LOGIN-{login_alert.get('ip', 'unknown')[:8]}-{len(alerts)}",
            'timestamp': login_alert.get('timestamp', datetime.now(timezone.utc).isoformat()),
            'attack_type': alert_type_map.get(login_alert.get('type'), 'LOGIN_ATTACK'),
            'severity': alert_severity,
            'source_ip': login_alert.get('ip'),
            'destination_ip': 'IDS Auth Server',
            'description': login_alert.get('message', 'Login attack detected'),
            'indicators': [
                f"Failed attempts: {login_alert.get('failed_attempts', 'N/A')}",
                f"Usernames tried: {', '.join(login_alert.get('attempted_usernames', [])[:5])}"
            ],
            'confidence': 0.95,
            'mitre_tactics': ['TA0006 - Credential Access', 'TA0001 - Initial Access'],
            'recommended_actions': [
                f"IP {login_alert.get('ip')} login blocked for {login_alert.get('lockout_minutes', 15)} minutes" if login_alert.get('type') == 'brute_force_detected' else 'Monitor for continued attempts',
                'Review authentication logs',
                'Consider IP blocking at firewall level'
            ]
        })
    
    # Sort by timestamp descending
    alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    return {
        "total": len(alerts),
        "alerts": alerts[:limit],
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
    
    # Add IP quarantine stats
    ip_stats = ip_quarantine.get_statistics()
    
    # Add suspicious activity counts
    suspicious_activities = network_monitor.get_suspicious_activities(limit=100)
    
    # Combine stats
    stats["alerts_generated"] = stats.get("alerts_generated", 0) + ip_stats.get("total_attacks_detected", 0) + len(suspicious_activities)
    
    # Count severities from suspicious activities
    for activity in suspicious_activities:
        sev = activity.get('severity', 'MEDIUM')
        stats["attacks_by_severity"][sev] = stats["attacks_by_severity"].get(sev, 0) + 1
        
        event_type = activity.get('event_type', 'unknown')
        stats["attacks_by_type"][event_type] = stats["attacks_by_type"].get(event_type, 0) + 1
        
        source = activity.get('source_ip', 'unknown')
        stats["top_attackers"][source] = stats["top_attackers"].get(source, 0) + 1
    
    # Add IP quarantine blocked IPs as attackers
    for blocked_ip in ip_quarantine.get_blocked_ips():
        ip = blocked_ip.get('ip', 'unknown')
        stats["top_attackers"][ip] = stats["top_attackers"].get(ip, 0) + 10  # Weight blocked IPs higher
        stats["attacks_by_severity"]["CRITICAL"] = stats["attacks_by_severity"].get("CRITICAL", 0) + 1
        stats["attacks_by_type"]["IP_BLOCKED"] = stats["attacks_by_type"].get("IP_BLOCKED", 0) + 1
    
    stats["data_source"] = "REAL_NETWORK_TRAFFIC"
    stats["ip_quarantine"] = {
        "currently_blocked": ip_stats.get("currently_blocked", 0),
        "total_attacks": ip_stats.get("total_attacks_detected", 0)
    }
    
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


# =============================================================================
# AUTHENTICATION ENDPOINTS
# =============================================================================
# User authentication and management for the IDS dashboard.

@app.post("/api/auth/login", tags=["Authentication"])
async def login(credentials: UserLogin, request: Request):
    """
    Authenticate user and return JWT token.
    
    **Rate Limited**: Max 5 failed attempts before 15-minute lockout.
    
    Default credentials:
    - Username: admin
    - Password: admin123
    """
    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    
    # Check X-Forwarded-For for proxy setups
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        client_ip = forwarded_for.split(',')[0].strip()
    
    # Check rate limit FIRST
    rate_check = login_rate_limiter.check_rate_limit(client_ip)
    if not rate_check['allowed']:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "Too many failed login attempts",
                "message": rate_check['reason'],
                "retry_after": rate_check['retry_after'],
                "failed_attempts": rate_check['failed_attempts']
            },
            headers={"Retry-After": str(rate_check['retry_after'])}
        )
    
    # Attempt login
    result = login_user(credentials.username, credentials.password)
    
    if result is None:
        # Record failed attempt
        attempt_result = login_rate_limiter.record_attempt(client_ip, credentials.username, success=False)
        
        detail = {
            "error": "Invalid username or password",
            "failed_attempts": attempt_result['failed_attempts'],
            "max_attempts": attempt_result['max_attempts']
        }
        
        if attempt_result.get('locked'):
            detail["locked"] = True
            detail["retry_after"] = attempt_result['retry_after']
            detail["message"] = attempt_result['message']
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=detail,
                headers={"Retry-After": str(attempt_result['retry_after'])}
            )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Record successful login
    login_rate_limiter.record_attempt(client_ip, credentials.username, success=True)
    logger.info(f"User logged in: {credentials.username} from {client_ip}")
    return result


@app.post("/api/auth/register", response_model=UserResponse, tags=["Authentication"])
async def register(user: UserCreate, current_user: Dict = Depends(require_role(["admin"]))):
    """
    Register a new user. Only admins can create new users.
    
    Roles available:
    - admin: Full access to all features
    - operator: Can view and respond to threats
    - viewer: Read-only access to dashboards
    """
    result = user_store.create_user(user)
    
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    logger.info(f"New user registered: {user.username} (by {current_user['username']})")
    return result


@app.get("/api/auth/me", tags=["Authentication"])
async def get_current_user_info(current_user: Dict = Depends(get_current_user)):
    """Get current authenticated user information"""
    user_data = user_store.get_user(current_user["username"])
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")
    
    return UserResponse(
        id=user_data["id"],
        username=user_data["username"],
        role=user_data["role"],
        created_at=user_data["created_at"],
        last_login=user_data.get("last_login"),
        is_active=user_data.get("is_active", True)
    )


@app.get("/api/auth/verify", tags=["Authentication"])
async def verify_current_token(current_user: Dict = Depends(get_current_user)):
    """Verify that the current token is valid"""
    return {
        "valid": True,
        "username": current_user["username"],
        "role": current_user["role"]
    }


@app.get("/api/auth/users", tags=["Authentication"])
async def list_users(current_user: Dict = Depends(require_role(["admin"]))):
    """List all users. Admin only."""
    return {
        "users": user_store.get_all_users(),
        "total": len(user_store.users)
    }


class UserUpdateRequest(BaseModel):
    password: Optional[str] = Field(None, min_length=6)
    role: Optional[str] = None
    is_active: Optional[bool] = None


@app.put("/api/auth/users/{username}", tags=["Authentication"])
async def update_user(
    username: str, 
    updates: UserUpdateRequest,
    current_user: Dict = Depends(require_role(["admin"]))
):
    """Update user. Admin only."""
    if username not in user_store.users:
        raise HTTPException(status_code=404, detail="User not found")
    
    update_dict = {}
    if updates.password:
        update_dict["password"] = updates.password
    if updates.role:
        update_dict["role"] = updates.role
    if updates.is_active is not None:
        update_dict["is_active"] = updates.is_active
    
    if update_dict:
        user_store.update_user(username, update_dict)
    
    return {"status": "success", "message": f"User {username} updated"}


@app.delete("/api/auth/users/{username}", tags=["Authentication"])
async def delete_user(username: str, current_user: Dict = Depends(require_role(["admin"]))):
    """Delete user. Admin only. Cannot delete yourself."""
    if username == current_user["username"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    if not user_store.delete_user(username):
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"status": "success", "message": f"User {username} deleted"}


@app.post("/api/auth/change-password", tags=["Authentication"])
async def change_password(
    old_password: str,
    new_password: str,
    current_user: Dict = Depends(get_current_user)
):
    """Change current user's password"""
    user = user_store.get_user(current_user["username"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify old password
    from .auth import verify_password
    if not verify_password(old_password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Update password
    user_store.update_user(current_user["username"], {"password": new_password})
    
    return {"status": "success", "message": "Password changed successfully"}


# =============================================================================
# LOGIN SECURITY / BRUTE FORCE DETECTION ENDPOINTS
# =============================================================================
# Monitor and manage login attempts, detect brute force attacks.

@app.get("/api/login-security/status", tags=["Login Security"])
async def get_login_security_status(current_user: Dict = Depends(get_current_user)):
    """Get login security status and statistics"""
    stats = login_rate_limiter.get_statistics()
    stats['timestamp'] = datetime.now(timezone.utc).isoformat()
    return stats


@app.get("/api/login-security/alerts", tags=["Login Security"])
async def get_login_alerts(
    limit: int = Query(50, ge=1, le=500),
    current_user: Dict = Depends(get_current_user)
):
    """Get recent login attack alerts"""
    alerts = login_rate_limiter.get_recent_alerts(limit=limit)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total": len(alerts),
        "alerts": alerts
    }


@app.get("/api/login-security/tracked-ips", tags=["Login Security"])
async def get_tracked_login_ips(
    limit: int = Query(50, ge=1, le=200),
    current_user: Dict = Depends(get_current_user)
):
    """Get all tracked IPs with login attempt info"""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tracked_ips": login_rate_limiter.get_all_trackers(limit=limit)
    }


@app.get("/api/login-security/ip/{ip_address}", tags=["Login Security"])
async def get_ip_login_status(
    ip_address: str,
    current_user: Dict = Depends(get_current_user)
):
    """Get login attempt status for specific IP"""
    status = login_rate_limiter.get_ip_status(ip_address)
    if status:
        return {
            "found": True,
            "ip_status": status
        }
    return {
        "found": False,
        "message": f"No login attempts tracked for IP: {ip_address}"
    }


@app.post("/api/login-security/unlock/{ip_address}", tags=["Login Security"])
async def unlock_ip_login(
    ip_address: str,
    current_user: Dict = Depends(require_role(["admin"]))
):
    """Manually unlock an IP that was locked due to failed logins. Admin only."""
    success = login_rate_limiter.unlock_ip(ip_address)
    if success:
        return {
            "status": "success",
            "message": f"IP {ip_address} has been unlocked"
        }
    return {
        "status": "not_found",
        "message": f"IP {ip_address} was not found or not locked"
    }


class LoginThresholdUpdate(BaseModel):
    max_attempts: Optional[int] = Field(None, ge=1, le=100)
    lockout_minutes: Optional[int] = Field(None, ge=1, le=1440)


@app.put("/api/login-security/thresholds", tags=["Login Security"])
async def update_login_thresholds(
    updates: LoginThresholdUpdate,
    current_user: Dict = Depends(require_role(["admin"]))
):
    """Update login rate limiting thresholds. Admin only."""
    old_values = {
        "max_attempts": login_rate_limiter.max_attempts,
        "lockout_minutes": login_rate_limiter.lockout_minutes
    }
    
    if updates.max_attempts is not None:
        login_rate_limiter.max_attempts = updates.max_attempts
    if updates.lockout_minutes is not None:
        login_rate_limiter.lockout_minutes = updates.lockout_minutes
    
    return {
        "status": "success",
        "old_values": old_values,
        "new_values": {
            "max_attempts": login_rate_limiter.max_attempts,
            "lockout_minutes": login_rate_limiter.lockout_minutes
        }
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


# =============================================================================
# IP QUARANTINE ENDPOINTS
# =============================================================================
# These endpoints manage IP-based attack detection and blocking.
# Works with the IPQuarantineMiddleware to detect and block attacking IPs.

class IPBlockRequest(BaseModel):
    ip: str = Field(..., description="IP address to block")
    reason: str = Field("Manual block", description="Reason for blocking")
    duration: int = Field(900, description="Block duration in seconds (0 for permanent)")


class IPUnblockRequest(BaseModel):
    ip: str = Field(..., description="IP address to unblock")


class IPThresholdUpdate(BaseModel):
    threshold_name: str = Field(..., description="Name of threshold to update")
    value: int = Field(..., description="New threshold value")


@app.get("/api/ip-quarantine/status", tags=["IP Quarantine"])
async def get_ip_quarantine_status():
    """Get overall IP quarantine system status and statistics"""
    stats = ip_quarantine.get_statistics()
    stats['blocked_ips'] = ip_quarantine.get_blocked_ips()
    return stats


@app.get("/api/ip-quarantine/blocked", tags=["IP Quarantine"])
async def get_blocked_ips():
    """Get all currently blocked IPs with details"""
    blocked = ip_quarantine.get_blocked_ips()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "blocked_count": len(blocked),
        "blocked_ips": blocked
    }


@app.get("/api/ip-quarantine/all-stats", tags=["IP Quarantine"])
async def get_all_ip_stats(limit: int = Query(50, ge=1, le=500)):
    """Get statistics for all tracked IPs (sorted by activity)"""
    all_stats = ip_quarantine.get_all_ip_stats(limit=limit)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_ips_tracked": len(ip_quarantine.ip_stats),
        "showing": len(all_stats),
        "ip_stats": all_stats
    }


@app.get("/api/ip-quarantine/ip/{ip_address}", tags=["IP Quarantine"])
async def get_ip_details(ip_address: str):
    """Get detailed statistics for a specific IP address"""
    stats = ip_quarantine.get_ip_stats(ip_address)
    if stats:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "found": True,
            "ip_stats": stats
        }
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "found": False,
        "message": f"No data for IP: {ip_address}"
    }


@app.get("/api/ip-quarantine/alerts", tags=["IP Quarantine"])
async def get_ip_attack_alerts(limit: int = Query(50, ge=1, le=500)):
    """Get recent IP-based attack alerts"""
    alerts = ip_quarantine.get_recent_alerts(limit=limit)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(alerts),
        "alerts": alerts
    }


@app.post("/api/ip-quarantine/block", tags=["IP Quarantine"])
async def manually_block_ip(request: IPBlockRequest):
    """Manually block an IP address"""
    from .ip_quarantine import BlockAction, IPRequestStats
    
    ip = request.ip
    now = datetime.now(timezone.utc)
    
    # Create or get stats for IP
    if ip not in ip_quarantine.ip_stats:
        ip_quarantine.ip_stats[ip] = IPRequestStats(
            ip=ip,
            first_seen=now,
            last_seen=now
        )
    
    stats = ip_quarantine.ip_stats[ip]
    stats.is_blocked = True
    stats.block_reason = request.reason
    stats.block_action = BlockAction.BLOCK if request.duration > 0 else BlockAction.PERMANENT
    stats.block_time = now
    stats.unblock_time = now + timedelta(seconds=request.duration) if request.duration > 0 else None
    
    ip_quarantine.blocked_ips[ip] = stats
    
    # Broadcast the block
    await manager.broadcast({
        'type': 'ip_blocked',
        'ip': ip,
        'reason': request.reason,
        'duration': request.duration,
        'timestamp': now.isoformat()
    })
    
    logger.info(f"🛑 Manually blocked IP: {ip} | Reason: {request.reason}")
    
    return {
        "status": "success",
        "message": f"IP {ip} has been blocked",
        "blocked_ip": stats.to_dict()
    }


@app.post("/api/ip-quarantine/unblock", tags=["IP Quarantine"])
async def manually_unblock_ip(request: IPUnblockRequest):
    """Manually unblock an IP address"""
    success = ip_quarantine.unblock_ip(request.ip)
    
    if success:
        # Broadcast the unblock
        await manager.broadcast({
            'type': 'ip_unblocked',
            'ip': request.ip,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
        return {
            "status": "success",
            "message": f"IP {request.ip} has been unblocked"
        }
    else:
        return {
            "status": "not_found",
            "message": f"IP {request.ip} was not blocked"
        }


@app.delete("/api/ip-quarantine/unblock-all", tags=["IP Quarantine"])
async def unblock_all_ips():
    """Unblock all currently blocked IPs (emergency reset)"""
    blocked_count = len(ip_quarantine.blocked_ips)
    ip_quarantine.clear_all_blocks()
    
    await manager.broadcast({
        'type': 'all_ips_unblocked',
        'count': blocked_count,
        'timestamp': datetime.now(timezone.utc).isoformat()
    })
    
    return {
        "status": "success",
        "message": f"Unblocked {blocked_count} IPs"
    }


@app.post("/api/ip-quarantine/whitelist/{ip_address}", tags=["IP Quarantine"])
async def add_to_whitelist(ip_address: str):
    """Add an IP to the whitelist (never block)"""
    ip_quarantine.add_to_whitelist(ip_address)
    return {
        "status": "success",
        "message": f"IP {ip_address} added to whitelist",
        "whitelist": list(ip_quarantine.whitelist)
    }


@app.delete("/api/ip-quarantine/whitelist/{ip_address}", tags=["IP Quarantine"])
async def remove_from_whitelist(ip_address: str):
    """Remove an IP from the whitelist"""
    ip_quarantine.remove_from_whitelist(ip_address)
    return {
        "status": "success",
        "message": f"IP {ip_address} removed from whitelist",
        "whitelist": list(ip_quarantine.whitelist)
    }


@app.get("/api/ip-quarantine/whitelist", tags=["IP Quarantine"])
async def get_whitelist():
    """Get all whitelisted IPs"""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "whitelist": list(ip_quarantine.whitelist)
    }


@app.put("/api/ip-quarantine/thresholds", tags=["IP Quarantine"])
async def update_threshold(request: IPThresholdUpdate):
    """Update a detection threshold"""
    if request.threshold_name not in ip_quarantine.thresholds:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown threshold: {request.threshold_name}. Available: {list(ip_quarantine.thresholds.keys())}"
        )
    
    old_value = ip_quarantine.thresholds[request.threshold_name]
    ip_quarantine.set_threshold(request.threshold_name, request.value)
    
    return {
        "status": "success",
        "threshold": request.threshold_name,
        "old_value": old_value,
        "new_value": request.value
    }


@app.get("/api/ip-quarantine/thresholds", tags=["IP Quarantine"])
async def get_thresholds():
    """Get current detection thresholds"""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "thresholds": ip_quarantine.thresholds,
        "descriptions": {
            'requests_per_minute_warn': 'Warning threshold (requests/min)',
            'requests_per_minute_throttle': 'Throttle threshold (requests/min)',
            'requests_per_minute_block': 'Block threshold (requests/min)',
            'endpoint_scan_threshold': 'Unique endpoints in 1 min to trigger scan detection',
            'failed_requests_threshold': 'Failed requests in 5 min for brute force detection',
            'burst_requests': 'Requests in burst window to trigger detection',
            'burst_window': 'Seconds for burst detection window'
        }
    }


# --- Combined Quarantine Dashboard ---

@app.get("/api/quarantine/dashboard", tags=["Quarantine"])
async def get_quarantine_dashboard():
    """Get combined quarantine dashboard with both process and IP quarantine data"""
    process_status = quarantine_system.get_quarantine_status()
    ip_stats = ip_quarantine.get_statistics()
    
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "process_quarantine": {
            "quarantined_count": len(quarantine_system.quarantined_processes),
            "killed_count": len(quarantine_system.killed_processes),
            "status": process_status
        },
        "ip_quarantine": {
            "blocked_count": len(ip_quarantine.blocked_ips),
            "tracked_ips": len(ip_quarantine.ip_stats),
            "total_attacks_detected": ip_stats['total_attacks_detected'],
            "blocked_ips": ip_quarantine.get_blocked_ips()[:10],  # Top 10
            "recent_alerts": ip_quarantine.get_recent_alerts(limit=10)
        },
        "combined_threat_level": _calculate_combined_threat_level(process_status, ip_stats)
    }


def _calculate_combined_threat_level(process_status: Dict, ip_stats: Dict) -> str:
    """Calculate combined threat level from both quarantine systems"""
    threat_score = 0
    
    # Process-based threats
    threat_score += len(quarantine_system.quarantined_processes) * 5
    threat_score += len(quarantine_system.killed_processes) * 3
    
    # IP-based threats
    threat_score += ip_stats.get('currently_blocked', 0) * 4
    threat_score += ip_stats.get('total_attacks_detected', 0) * 2
    
    if threat_score >= 50:
        return "CRITICAL"
    elif threat_score >= 30:
        return "HIGH"
    elif threat_score >= 15:
        return "MEDIUM"
    elif threat_score >= 5:
        return "LOW"
    else:
        return "NORMAL"
