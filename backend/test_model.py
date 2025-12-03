#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')

from app.ml_models import AnomalyDetector, NSLKDDDataLoader
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import warnings
warnings.filterwarnings('ignore')

# Load test data
loader = NSLKDDDataLoader()
df = loader.load_dataset('csv_result-KDDTest.csv')

if df is not None:
    X, y = loader.preprocess_data(df)
    
    detector = AnomalyDetector()
    detector.load_model()
    
    X_scaled = detector.scaler.transform(X)
    y_pred = detector.random_forest.predict(X_scaled)
    
    print('=== CURRENT MODEL PERFORMANCE ON TEST SET ===')
    print(f'Test samples: {len(y)}')
    print(f'Accuracy:  {accuracy_score(y, y_pred):.4f}')
    print(f'Precision: {precision_score(y, y_pred):.4f}')
    print(f'Recall:    {recall_score(y, y_pred):.4f}')
    print(f'F1 Score:  {f1_score(y, y_pred):.4f}')
    
    tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()
    print(f'\nConfusion Matrix:')
    print(f'  True Negatives:  {tn:5d} (correctly identified normal)')
    print(f'  False Positives: {fp:5d} (false alarms)')
    print(f'  False Negatives: {fn:5d} (missed attacks)')
    print(f'  True Positives:  {tp:5d} (correctly identified attacks)')
