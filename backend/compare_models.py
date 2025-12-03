#!/usr/bin/env python3
"""Compare different ML models for intrusion detection"""
import sys
sys.path.insert(0, '.')

import warnings
warnings.filterwarnings('ignore')

from app.ml_models import NSLKDDDataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
import time

# Models to test
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, AdaBoostClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier

# Try XGBoost if available
try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("XGBoost not installed - skipping")

# Try LightGBM if available
try:
    from lightgbm import LGBMClassifier
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False
    print("LightGBM not installed - skipping")

print("Loading NSL-KDD dataset...")
loader = NSLKDDDataLoader()

# Load training data (20% subset for speed)
train_df = loader.load_dataset('csv_result-KDDTrain_20Percent.csv')
X_train, y_train = loader.preprocess_data(train_df)

# Load test data - need to handle unseen labels
test_df = loader.load_dataset('csv_result-KDDTest.csv')

# Handle unseen categorical values in test set
for feature in loader.categorical_features:
    if feature in test_df.columns and feature in loader.label_encoders:
        le = loader.label_encoders[feature]
        # Replace unseen values with the most common value from training
        test_df[feature] = test_df[feature].apply(
            lambda x: x if x in le.classes_ else le.classes_[0]
        )

X_test, y_test = loader.preprocess_data(test_df)

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print(f"\nTraining samples: {len(X_train)}")
print(f"Test samples: {len(X_test)}")
print(f"Features: {X_train.shape[1]}")

# Define models to test
models = {
    'Random Forest (current)': RandomForestClassifier(
        n_estimators=100, max_depth=20, random_state=42, n_jobs=-1
    ),
    'Random Forest (tuned)': RandomForestClassifier(
        n_estimators=200, max_depth=15, min_samples_split=5, 
        min_samples_leaf=2, class_weight='balanced', random_state=42, n_jobs=-1
    ),
    'Gradient Boosting': GradientBoostingClassifier(
        n_estimators=100, max_depth=5, random_state=42
    ),
    'Decision Tree': DecisionTreeClassifier(
        max_depth=15, random_state=42
    ),
    'Logistic Regression': LogisticRegression(
        max_iter=1000, random_state=42, n_jobs=-1
    ),
    'K-Nearest Neighbors': KNeighborsClassifier(
        n_neighbors=5, n_jobs=-1
    ),
    'Naive Bayes': GaussianNB(),
    'AdaBoost': AdaBoostClassifier(
        n_estimators=100, random_state=42
    ),
}

if HAS_XGBOOST:
    models['XGBoost'] = XGBClassifier(
        n_estimators=100, max_depth=6, learning_rate=0.1,
        random_state=42, n_jobs=-1, verbosity=0
    )

if HAS_LIGHTGBM:
    models['LightGBM'] = LGBMClassifier(
        n_estimators=100, max_depth=6, learning_rate=0.1,
        random_state=42, n_jobs=-1, verbosity=-1
    )

# Test each model
print("\n" + "="*80)
print(f"{'Model':<30} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Time':>8}")
print("="*80)

results = []

for name, model in models.items():
    start = time.time()
    
    # Train
    model.fit(X_train_scaled, y_train)
    
    # Predict
    y_pred = model.predict(X_test_scaled)
    
    elapsed = time.time() - start
    
    # Metrics
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    results.append({
        'name': name, 'accuracy': acc, 'precision': prec, 
        'recall': rec, 'f1': f1, 'time': elapsed
    })
    
    print(f"{name:<30} {acc:>10.4f} {prec:>10.4f} {rec:>10.4f} {f1:>10.4f} {elapsed:>7.2f}s")

# Sort by F1 score
print("\n" + "="*80)
print("RANKING BY F1 SCORE (best overall balance):")
print("="*80)
for i, r in enumerate(sorted(results, key=lambda x: x['f1'], reverse=True), 1):
    print(f"{i}. {r['name']:<30} F1={r['f1']:.4f}  Recall={r['recall']:.4f}")

print("\n" + "="*80)
print("RANKING BY RECALL (catches most attacks):")
print("="*80)
for i, r in enumerate(sorted(results, key=lambda x: x['recall'], reverse=True), 1):
    print(f"{i}. {r['name']:<30} Recall={r['recall']:.4f}  Precision={r['precision']:.4f}")
