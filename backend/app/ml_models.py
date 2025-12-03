# backend/app/ml_models.py
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from typing import Dict, List, Any, Optional, Tuple
import joblib
import os
from datetime import datetime
import logging
import asyncio
import warnings

# Suppress specific sklearn warnings about feature names
warnings.filterwarnings('ignore', category=UserWarning, module='sklearn.utils.validation')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NSLKDDDataLoader:
    """Load and preprocess NSL-KDD dataset for intrusion detection"""
    
    def __init__(self, data_path: str = "../NSL-KDD/"):
        # Use absolute path based on current file location
        if not os.path.isabs(data_path):
            current_dir = os.path.dirname(os.path.abspath(__file__))
            backend_dir = os.path.dirname(current_dir)
            project_dir = os.path.dirname(backend_dir)
            data_path = os.path.join(project_dir, "NSL-KDD")
        self.data_path = data_path
        self.feature_columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
        ]
        self.categorical_features = ['protocol_type', 'service', 'flag']
        self.label_encoders = {}
        
    def load_dataset(self, filename: str = "csv_result-KDDTrain_20Percent.csv") -> pd.DataFrame:
        """Load NSL-KDD dataset from CSV file"""
        try:
            filepath = os.path.join(self.data_path, filename)
            logger.info(f"Loading NSL-KDD dataset from {filepath}")
            
            # Read CSV file
            df = pd.read_csv(filepath)
            
            # Clean column names (remove quotes)
            df.columns = [col.strip("'") for col in df.columns]
            
            # Drop the 'id' column if it exists
            if 'id' in df.columns:
                df = df.drop('id', axis=1)
            
            # Clean the 'class' column (remove extra spaces)
            if 'class' in df.columns:
                df['class'] = df['class'].str.strip()
            
            logger.info(f"Loaded {len(df)} samples with {len(df.columns)} features")
            logger.info(f"Attack type distribution:")
            if 'class' in df.columns:
                logger.info(df['class'].value_counts())
            
            return df
            
        except Exception as e:
            logger.error(f"Error loading NSL-KDD dataset: {str(e)}")
            return None
    
    def preprocess_data(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
        """Preprocess NSL-KDD data for ML training"""
        # Create binary labels (normal=0, anomaly=1)
        y = (df['class'] != 'normal').astype(int)
        
        # Select feature columns
        X = df[self.feature_columns].copy()
        
        # Handle categorical features
        for feature in self.categorical_features:
            if feature in X.columns:
                if feature not in self.label_encoders:
                    self.label_encoders[feature] = LabelEncoder()
                    X[feature] = self.label_encoders[feature].fit_transform(X[feature].astype(str))
                else:
                    X[feature] = self.label_encoders[feature].transform(X[feature].astype(str))
        
        # Handle missing values
        X = X.fillna(0)
        
        # Convert to numeric
        for col in X.columns:
            X[col] = pd.to_numeric(X[col], errors='coerce')
        X = X.fillna(0)
        
        logger.info(f"Preprocessed data shape: {X.shape}")
        logger.info(f"Normal samples: {(y == 0).sum()}, Anomaly samples: {(y == 1).sum()}")
        
        return X, y

class AnomalyDetector:
    """ML-based anomaly detection using NSL-KDD dataset"""
    
    def __init__(self, model_path: str = "models/"):
        # Use absolute path based on current file location
        if not os.path.isabs(model_path):
            current_dir = os.path.dirname(os.path.abspath(__file__))
            backend_dir = os.path.dirname(current_dir)
            model_path = os.path.join(backend_dir, model_path)
        self.model_path = model_path
        self.isolation_forest = None
        self.random_forest = None
        self.scaler = StandardScaler()
        self.data_loader = NSLKDDDataLoader()
        self.feature_columns = []
        self.is_trained = False
        
        # Ensure model directory exists
        os.makedirs(model_path, exist_ok=True)
    
    def map_network_data_to_nslkdd_features(self, network_data: Dict[str, Any]) -> Dict[str, float]:
        """Map REAL network monitoring data to NSL-KDD feature format"""
        # Map our REAL network data to NSL-KDD features
        
        # ===== REAL VALUES from NetworkMonitor =====
        nsl_features = {
            # Duration - REAL: tracked from connection start time
            'duration': float(network_data.get('connection_duration', 0)),
            
            # Protocol - REAL: from psutil connection type
            'protocol_type': float(network_data.get('protocol_type', 1)),  # TCP=1, UDP=2
            
            # Service - mapped from port
            'service': self._encode_service(network_data.get('dst_port', 0)),
            
            # Flag - mapped from connection status
            'flag': self._encode_flag(network_data.get('status', 'ESTABLISHED')),
            
            # Bytes - REAL: from network I/O monitoring
            'src_bytes': float(network_data.get('src_bytes', network_data.get('bytes_per_second', 0))),
            'dst_bytes': float(network_data.get('dst_bytes', network_data.get('bytes_per_second', 0))),
            
            # Land attack detection (src=dst)
            'land': 1.0 if network_data.get('src_ip') == network_data.get('dst_ip') else 0.0,
            
            # ===== PACKET-LEVEL FEATURES - REAL from Scapy packet capture =====
            # These require packet-level inspection and are now tracked by PacketAnalyzer
            'wrong_fragment': float(network_data.get('wrong_fragment', 0)),  # REAL: from IP fragmentation analysis
            'urgent': float(network_data.get('urgent', 0)),  # REAL: from TCP URG flag detection
            
            # Hot indicators - detect from port access patterns
            'hot': self._calculate_hot_indicator(network_data),
            
            # Login features - REAL: from login_rate_limiter via network monitor
            'num_failed_logins': float(network_data.get('num_failed_logins', 0)),
            'logged_in': float(network_data.get('is_logged_in', 1 if network_data.get('status') == 'ESTABLISHED' else 0)),
            
            # Compromise indicators - REAL: from login tracking and packet analysis
            'num_compromised': float(network_data.get('num_compromised', 0)),  # REAL: from payload analysis
            'root_shell': float(network_data.get('num_root', 0)),
            'su_attempted': float(network_data.get('su_attempted', 0)),
            'num_root': float(network_data.get('num_root', 0)),
            'num_file_creations': float(network_data.get('num_file_creations', 0)),  # REAL from process monitoring
            'num_shells': float(network_data.get('num_shells', 0)),  # REAL from process monitoring
            'num_access_files': float(network_data.get('num_access_files', 0)),  # REAL from process monitoring
            'num_outbound_cmds': float(network_data.get('num_outbound_cmds', 0)),  # REAL: outbound command connections
            'is_host_login': float(network_data.get('is_host_login', 0)),
            'is_guest_login': float(network_data.get('is_guest_login', 0)),
            
            # ===== TRAFFIC FEATURES - REAL from NetworkMonitor =====
            # Count - REAL: connections to same host in time window
            'count': min(255.0, float(network_data.get('count', 1))),
            
            # Srv_count - REAL: connections to same service
            'srv_count': min(255.0, float(network_data.get('srv_count', 1))),
            
            # Error rates - REAL: calculated from connection states
            'serror_rate': float(network_data.get('serror_rate', 0.0)),
            'srv_serror_rate': float(network_data.get('srv_serror_rate', 0.0)),
            'rerror_rate': float(network_data.get('rerror_rate', 0.0)),
            'srv_rerror_rate': float(network_data.get('srv_rerror_rate', 0.0)),
            
            # Service rates - REAL: calculated from service access patterns
            'same_srv_rate': float(network_data.get('same_srv_rate', 1.0)),
            'diff_srv_rate': float(network_data.get('diff_srv_rate', 0.0)),
            'srv_diff_host_rate': float(network_data.get('srv_diff_host_rate', 0.0)),  # REAL: multi-host tracking
            
            # ===== HOST-BASED FEATURES - REAL from NetworkMonitor =====
            'dst_host_count': min(255.0, float(network_data.get('dst_host_count', 1))),
            'dst_host_srv_count': min(255.0, float(network_data.get('dst_host_srv_count', 1))),
            'dst_host_same_srv_rate': float(network_data.get('dst_host_same_srv_rate', 1.0)),
            'dst_host_diff_srv_rate': float(network_data.get('dst_host_diff_srv_rate', 0.0)),
            'dst_host_same_src_port_rate': float(network_data.get('dst_host_same_src_port_rate', 1.0)),  # REAL: port pattern tracking
            'dst_host_srv_diff_host_rate': float(network_data.get('dst_host_srv_diff_host_rate', 0.0)),  # REAL: multi-host tracking
            'dst_host_serror_rate': float(network_data.get('dst_host_serror_rate', 0.0)),
            'dst_host_srv_serror_rate': float(network_data.get('dst_host_srv_serror_rate', 0.0)),
            'dst_host_rerror_rate': float(network_data.get('dst_host_rerror_rate', 0.0)),
            'dst_host_srv_rerror_rate': float(network_data.get('dst_host_srv_rerror_rate', 0.0)),
        }
        
        # ===== ENHANCE with attack-specific patterns =====
        event_type = network_data.get('event_type', '')
        
        # Port scan detection
        if event_type == 'port_scan' or network_data.get('ports_scanned', 0) > 5:
            nsl_features['count'] = max(nsl_features['count'], 50.0)
            nsl_features['diff_srv_rate'] = 0.9
            nsl_features['same_srv_rate'] = 0.1
            nsl_features['dst_host_diff_srv_rate'] = 0.9
        
        # DDoS / high traffic detection
        packets_per_sec = network_data.get('packets_per_second', 0)
        if packets_per_sec > 100:
            nsl_features['count'] = min(255.0, float(packets_per_sec))
            nsl_features['serror_rate'] = min(1.0, packets_per_sec / 500.0)
        
        # Brute force detection
        if event_type == 'brute_force' or network_data.get('failed_logins', 0) > 3:
            nsl_features['num_failed_logins'] = float(network_data.get('failed_logins', 5))
            nsl_features['logged_in'] = 0.0
            nsl_features['serror_rate'] = 0.5
        
        return nsl_features
    
    def _encode_service(self, port: int) -> float:
        """Encode port to service category (0-70 range like NSL-KDD)"""
        service_encoding = {
            20: 1, 21: 2, 22: 3, 23: 4, 25: 5,  # ftp-data, ftp, ssh, telnet, smtp
            53: 6, 80: 7, 110: 8, 143: 9, 443: 10,  # dns, http, pop3, imap, https
            445: 11, 993: 12, 995: 13, 3306: 14, 3389: 15,  # smb, imaps, pop3s, mysql, rdp
            5432: 16, 6379: 17, 27017: 18, 8080: 19, 8443: 20  # postgresql, redis, mongodb, http-alt
        }
        return float(service_encoding.get(port, 0))
    
    def _encode_flag(self, status: str) -> float:
        """Encode connection status to flag (0-11 range like NSL-KDD)"""
        flag_encoding = {
            'ESTABLISHED': 0, 'SYN_SENT': 1, 'SYN_RECV': 2, 
            'FIN_WAIT1': 3, 'FIN_WAIT2': 4, 'TIME_WAIT': 5,
            'CLOSE': 6, 'CLOSE_WAIT': 7, 'LAST_ACK': 8,
            'LISTEN': 9, 'CLOSING': 10, 'NONE': 11
        }
        return float(flag_encoding.get(status, 0))
    
    def _calculate_hot_indicator(self, network_data: Dict) -> float:
        """Calculate 'hot' indicator based on access patterns"""
        hot = 0.0
        
        # Suspicious ports increase hot indicator
        suspicious_ports = {23, 135, 139, 445, 1433, 3306, 3389, 5900}
        if network_data.get('dst_port') in suspicious_ports:
            hot += 2.0
        
        # High connection rate increases hot
        if network_data.get('count', 0) > 20:
            hot += 1.0
        
        # Error conditions increase hot
        if network_data.get('serror_rate', 0) > 0.3:
            hot += 1.0
            
        return min(hot, 10.0)  # Cap at 10
    
    def train_model_with_nslkdd(self, use_subset: bool = True) -> bool:
        """Train models using NSL-KDD dataset"""
        try:
            # Load NSL-KDD training data
            filename = "csv_result-KDDTrain_20Percent.csv" if use_subset else "csv_result-KDDTrain.csv"
            df = self.data_loader.load_dataset(filename)
            
            if df is None:
                logger.error("Failed to load NSL-KDD dataset")
                return False
            
            # Preprocess data
            X, y = self.data_loader.preprocess_data(df)
            self.feature_columns = list(X.columns)
            
            # Split data for validation
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train Isolation Forest (unsupervised)
            logger.info("Training Isolation Forest model...")
            contamination = y_train.mean()  # Use actual anomaly rate
            self.isolation_forest = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100,
                max_samples='auto',
                n_jobs=-1
            )
            self.isolation_forest.fit(X_train_scaled)
            
            # Train Random Forest (supervised) for comparison
            # Using regularization to prevent overfitting
            logger.info("Training Random Forest classifier...")
            self.random_forest = RandomForestClassifier(
                n_estimators=150,           # More trees for stability
                random_state=42,
                max_depth=10,               # Reduced from 20 to prevent overfitting
                min_samples_split=10,       # Require at least 10 samples to split
                min_samples_leaf=5,         # Each leaf must have at least 5 samples
                max_features='sqrt',        # Use sqrt(n_features) for each split
                class_weight='balanced',    # Handle imbalanced classes
                n_jobs=-1
            )
            self.random_forest.fit(X_train_scaled, y_train)
            
            # Evaluate models (pass train data to detect overfitting)
            self._evaluate_models(X_test_scaled, y_test, X_train_scaled, y_train)
            
            # Save models
            self._save_models()
            
            self.is_trained = True
            logger.info("NSL-KDD model training completed successfully!")
            return True
            
        except Exception as e:
            logger.error(f"Error training NSL-KDD model: {str(e)}")
            return False
    
    def _evaluate_models(self, X_test: np.ndarray, y_test: np.ndarray, X_train: np.ndarray = None, y_train: np.ndarray = None):
        """Evaluate trained models on test data with overfitting detection"""
        # Evaluate Isolation Forest
        if_predictions = self.isolation_forest.predict(X_test)
        if_predictions = (if_predictions == -1).astype(int)  # Convert -1/1 to 0/1
        
        # Evaluate Random Forest on TEST data
        rf_predictions_test = self.random_forest.predict(X_test)
        test_accuracy = (rf_predictions_test == y_test).mean()
        
        logger.info("=== Isolation Forest Results ===")
        logger.info(f"Test Accuracy: {(if_predictions == y_test).mean():.3f}")
        
        logger.info("=== Random Forest Results ===")
        logger.info(f"Test Accuracy: {test_accuracy:.3f}")
        
        # Check for overfitting by comparing train vs test accuracy
        if X_train is not None and y_train is not None:
            rf_predictions_train = self.random_forest.predict(X_train)
            train_accuracy = (rf_predictions_train == y_train).mean()
            logger.info(f"Train Accuracy: {train_accuracy:.3f}")
            
            # Overfitting indicator
            accuracy_gap = train_accuracy - test_accuracy
            if accuracy_gap > 0.05:  # More than 5% gap
                logger.warning(f"⚠️ OVERFITTING DETECTED: Train-Test gap = {accuracy_gap:.3f}")
                logger.warning("Consider: reducing max_depth, increasing min_samples_split")
            else:
                logger.info(f"✅ No significant overfitting (gap: {accuracy_gap:.3f})")
        
        logger.info("\nDetailed Classification Report (Test Data):")
        logger.info(classification_report(y_test, rf_predictions_test, target_names=['Normal', 'Anomaly']))
    
    def _save_models(self):
        """Save trained models to disk"""
        model_files = {
            'isolation_forest.pkl': self.isolation_forest,
            'random_forest.pkl': self.random_forest,
            'scaler.pkl': self.scaler,
            'features.pkl': self.feature_columns,
            'label_encoders.pkl': self.data_loader.label_encoders
        }
        
        for filename, model_obj in model_files.items():
            filepath = os.path.join(self.model_path, filename)
            joblib.dump(model_obj, filepath)
            logger.info(f"Saved {filename}")

    def train_model(self, training_data: Optional[pd.DataFrame] = None) -> bool:
        """Train the anomaly detection model (wrapper for NSL-KDD training)"""
        return self.train_model_with_nslkdd(use_subset=True)
    
    def load_model(self) -> bool:
        """Load pre-trained NSL-KDD model from disk"""
        try:
            model_files = ['isolation_forest.pkl', 'scaler.pkl', 'features.pkl', 'label_encoders.pkl']
            model_paths = [os.path.join(self.model_path, f) for f in model_files]
            
            if all(os.path.exists(path) for path in model_paths):
                self.isolation_forest = joblib.load(model_paths[0])
                self.scaler = joblib.load(model_paths[1])
                self.feature_columns = joblib.load(model_paths[2])
                self.data_loader.label_encoders = joblib.load(model_paths[3])
                
                # Try to load Random Forest if available
                rf_path = os.path.join(self.model_path, 'random_forest.pkl')
                if os.path.exists(rf_path):
                    self.random_forest = joblib.load(rf_path)
                
                self.is_trained = True
                logger.info("NSL-KDD models loaded successfully!")
                return True
            else:
                logger.info("No pre-trained NSL-KDD models found. Training new models...")
                return self.train_model_with_nslkdd()
                
        except Exception as e:
            logger.error(f"Error loading NSL-KDD models: {str(e)}")
            return self.train_model_with_nslkdd()
    
    def predict_anomaly(self, network_data: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        """Predict if network data represents an anomaly using NSL-KDD trained models"""
        if not self.is_trained:
            if not self.load_model():
                raise Exception("NSL-KDD model not trained and training failed")
        
        try:
            # Map network data to NSL-KDD features
            features = self.map_network_data_to_nslkdd_features(network_data)
            
            # Ensure all required features are present
            feature_vector = []
            for col in self.feature_columns:
                feature_vector.append(features.get(col, 0.0))
            
            # Create DataFrame with proper column names to avoid sklearn warnings
            X = pd.DataFrame([feature_vector], columns=self.feature_columns)
            X_scaled = self.scaler.transform(X)
            
            # Predict with Isolation Forest
            if_prediction = self.isolation_forest.predict(X_scaled)[0]
            if_score = self.isolation_forest.decision_function(X_scaled)[0]
            
            is_anomaly_if = if_prediction == -1
            confidence_if = abs(if_score)
            
            # Also predict with Random Forest if available
            rf_prediction = None
            rf_confidence = 0.0
            if self.random_forest:
                rf_prediction = self.random_forest.predict(X_scaled)[0]
                rf_proba = self.random_forest.predict_proba(X_scaled)[0]
                rf_confidence = max(rf_proba)
            
            # Combine predictions (prefer Random Forest if available)
            if self.random_forest:
                is_anomaly = bool(rf_prediction)
                confidence = float(rf_confidence)
                primary_method = "Random Forest"
            else:
                is_anomaly = is_anomaly_if
                confidence = confidence_if
                primary_method = "Isolation Forest"
            
            # Create detailed analysis
            analysis = {
                'primary_prediction': 'ANOMALY' if is_anomaly else 'NORMAL',
                'primary_method': primary_method,
                'confidence_score': float(confidence),
                'isolation_forest': {
                    'prediction': 'ANOMALY' if is_anomaly_if else 'NORMAL',
                    'anomaly_score': float(if_score),
                    'confidence': float(confidence_if)
                },
                'features_analyzed': features,
                'nsl_kdd_based': True,
                'timestamp': datetime.now().isoformat()
            }
            
            if self.random_forest:
                analysis['random_forest'] = {
                    'prediction': 'ANOMALY' if rf_prediction else 'NORMAL',
                    'confidence': float(rf_confidence),
                    'probabilities': {
                        'normal': float(rf_proba[0]),
                        'anomaly': float(rf_proba[1])
                    }
                }
            
            return is_anomaly, confidence, analysis
            
        except Exception as e:
            logger.error(f"Error predicting anomaly with NSL-KDD model: {str(e)}")
            return False, 0.0, {'error': str(e), 'nsl_kdd_based': True}

class ThreatIntelligence:
    """Threat intelligence and scoring system"""
    
    def __init__(self):
        self.known_malicious_ips = set([
            '192.168.1.100',  # Example malicious IPs
            '10.0.0.50',
            '172.16.0.25'
        ])
        
        self.suspicious_ports = {
            1433: 'SQL Server',
            3389: 'RDP',
            23: 'Telnet',
            135: 'RPC',
            445: 'SMB'
        }
    
    def analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """Analyze IP address for threats"""
        threat_score = 0
        indicators = []
        
        if ip_address in self.known_malicious_ips:
            threat_score += 8
            indicators.append('Known malicious IP')
        
        # Check for private IP ranges (could be internal threats)
        if ip_address.startswith('192.168.') or ip_address.startswith('10.') or ip_address.startswith('172.'):
            if ip_address in self.known_malicious_ips:
                threat_score += 5
                indicators.append('Internal threat detected')
        
        return {
            'ip_address': ip_address,
            'threat_score': threat_score,
            'max_score': 10,
            'risk_level': self._get_risk_level(threat_score),
            'indicators': indicators,
            'analysis_time': datetime.now().isoformat()
        }
    
    def analyze_port_activity(self, port: int, activity_type: str) -> Dict[str, Any]:
        """Analyze port activity for suspicious behavior"""
        threat_score = 0
        indicators = []
        
        if port in self.suspicious_ports:
            threat_score += 6
            indicators.append(f'Suspicious port activity: {self.suspicious_ports[port]}')
        
        if activity_type == 'scan':
            threat_score += 7
            indicators.append('Port scanning detected')
        
        return {
            'port': port,
            'activity_type': activity_type,
            'threat_score': threat_score,
            'max_score': 10,
            'risk_level': self._get_risk_level(threat_score),
            'indicators': indicators,
            'analysis_time': datetime.now().isoformat()
        }
    
    def _get_risk_level(self, score: int) -> str:
        """Convert numeric score to risk level"""
        if score >= 8:
            return 'CRITICAL'
        elif score >= 6:
            return 'HIGH'
        elif score >= 4:
            return 'MEDIUM'
        elif score >= 2:
            return 'LOW'
        else:
            return 'MINIMAL'

# Global instances
anomaly_detector = AnomalyDetector()
threat_intel = ThreatIntelligence()

async def initialize_ml_models():
    """Initialize ML models on startup"""
    logger.info("Initializing ML models...")
    
    # Load or train anomaly detection model
    success = anomaly_detector.load_model()
    if success:
        logger.info("ML models initialized successfully!")
    else:
        logger.error("Failed to initialize ML models!")
    
    return success