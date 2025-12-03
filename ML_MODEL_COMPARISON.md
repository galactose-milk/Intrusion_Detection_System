# ML Model Comparison for Intrusion Detection System

## Dataset: NSL-KDD
- **Training samples**: 25,192 (20% subset)
- **Test samples**: 22,544
- **Features**: 41 NSL-KDD network traffic features
- **Classes**: Binary (Normal vs Anomaly)

## Model Comparison Results

| Rank | Model | Accuracy | Precision | Recall | F1 Score | Time |
|------|-------|----------|-----------|--------|----------|------|
| 🥇 | **Decision Tree** | 0.8122 | 0.9372 | **0.7183** | **0.8133** | 0.19s |
| 🥈 | AdaBoost | 0.7987 | 0.9661 | 0.6700 | 0.7912 | 6.85s |
| 🥉 | XGBoost | 0.7956 | 0.9671 | 0.6634 | 0.7870 | 2.48s |
| 4 | Gradient Boosting | 0.7885 | 0.9673 | 0.6504 | 0.7778 | 8.08s |
| 5 | Naive Bayes | 0.7809 | 0.9242 | 0.6700 | 0.7768 | 0.20s |
| 6 | LightGBM | 0.7867 | 0.9661 | 0.6480 | 0.7757 | 1.44s |
| 7 | Random Forest (current) | 0.7794 | 0.9671 | 0.6340 | 0.7659 | 0.61s |
| 8 | Random Forest (tuned) | 0.7725 | 0.9672 | 0.6214 | 0.7567 | 1.17s |
| 9 | K-Nearest Neighbors | 0.7717 | 0.9727 | 0.6163 | 0.7545 | 8.24s |
| 10 | Logistic Regression | 0.7540 | 0.9255 | 0.6176 | 0.7409 | 1.99s |

## Key Findings

### 1. Decision Tree is the Winner
- **Best F1 Score**: 0.8133 (5% better than Random Forest)
- **Best Recall**: 0.7183 (catches 72% of attacks vs 63%)
- **Fastest**: 0.19 seconds training time
- **Simplest**: Easy to interpret and explain

### 2. XGBoost/LightGBM NOT Superior Here
- Despite common belief, gradient boosting methods didn't outperform simpler models
- XGBoost: F1=0.7870 (rank 3)
- LightGBM: F1=0.7757 (rank 6)

### 3. Current Random Forest is Average
- Ranks 7th out of 10 models
- Misses 36% of attacks (4,644 out of 12,833)

### 4. Tuning Can Hurt Performance
- "Tuned" Random Forest performed WORSE than default
- Over-regularization reduced recall

## Feature Importance (Top 10)

| Feature | Importance |
|---------|------------|
| src_bytes | 0.1980 |
| dst_bytes | 0.0977 |
| same_srv_rate | 0.0818 |
| flag | 0.0683 |
| dst_host_same_srv_rate | 0.0653 |
| dst_host_srv_count | 0.0613 |
| logged_in | 0.0472 |
| protocol_type | 0.0339 |
| diff_srv_rate | 0.0336 |
| count | 0.0332 |

## Recommendation

**Switch from Random Forest to Decision Tree** for:
- +9% better attack detection (recall)
- +5% better overall performance (F1)
- 3x faster inference
- Simpler model explanation

## Test Configuration

```python
# Decision Tree (Recommended)
DecisionTreeClassifier(max_depth=15, random_state=42)

# Current Random Forest
RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42)
```

## NSL-KDD Features Used (41 total)

All 41 features are now populated with **REAL network data**:

### Basic Features (Real)
- duration, protocol_type, service, flag
- src_bytes, dst_bytes, land

### Content Features (Real)
- wrong_fragment, urgent (from Scapy)
- hot, num_failed_logins, logged_in
- num_compromised, root_shell, su_attempted
- num_root, num_file_creations, num_shells
- num_access_files, num_outbound_cmds
- is_host_login, is_guest_login

### Traffic Features (Real)
- count, srv_count
- serror_rate, srv_serror_rate
- rerror_rate, srv_rerror_rate
- same_srv_rate, diff_srv_rate
- srv_diff_host_rate

### Host-based Features (Real)
- dst_host_count, dst_host_srv_count
- dst_host_same_srv_rate, dst_host_diff_srv_rate
- dst_host_same_src_port_rate, dst_host_srv_diff_host_rate
- dst_host_serror_rate, dst_host_srv_serror_rate
- dst_host_rerror_rate, dst_host_srv_rerror_rate

---
*Generated: December 3, 2025*
*Test Script: backend/compare_models.py*
