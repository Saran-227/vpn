#!/usr/bin/env python3
"""
SIH26160 IPsec Traffic Analysis - AI Model Training Pipeline
Trains high-performance classifiers for:
  1. Multi-Class Encrypted Traffic Profile Identification (VoIP, Video, Web, Chat, Email, Bulk, ICMP, Mixed)
  2. Operational Mode Classification (Tunnel vs Transport)
Outputs trained models, confusion matrices, and feature importance rankings.
"""

import os
import json
import argparse
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
import xgboost as xgb
import joblib


NUMERIC_FEATURES = [
    'pkt_count', 'byte_count', 'duration_sec', 'byte_rate', 'pkt_rate',
    'pkt_len_mean', 'pkt_len_std', 'pkt_len_min', 'pkt_len_max',
    'pkt_len_median', 'pkt_len_q25', 'pkt_len_q75', 'pkt_len_skew',
    'iat_mean', 'iat_std', 'iat_min', 'iat_max',
    'iat_q10', 'iat_q50', 'iat_q90', 'burstiness_coeff',
    'fwd_pkt_ratio', 'fwd_byte_ratio', 'bwd_pkt_ratio', 'bwd_byte_ratio',
    'fwd_bwd_iat_ratio',
    'small_pkt_ratio', 'med_pkt_ratio', 'large_pkt_ratio', 'bimodal_index',
    'esp_spi_count', 'seq_gap_rate'
]


def load_and_preprocess(csv_path):
    """
    Loads dataset/features.csv and prepares feature matrices.
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Feature dataset not found: {csv_path}")

    df = pd.read_csv(csv_path)
    print(f"[*] Loaded feature dataset: {len(df)} samples, {len(df.columns)} columns")

    # Clean missing or infinite values
    for col in NUMERIC_FEATURES:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)
            df[col] = df[col].replace([np.inf, -np.inf], 0.0)
        else:
            df[col] = 0.0

    X = df[NUMERIC_FEATURES].values
    return df, X


def train_traffic_classifier(df, X, output_dir):
    """
    Trains Multi-Class Traffic Profile Classifier using XGBoost & Random Forest.
    """
    print("\n=======================================================")
    print("  TRAINING MODEL 1: ENCRYPTED TRAFFIC PROFILE CLASSIFIER")
    print("=======================================================")

    le_class = LabelEncoder()
    y_class = le_class.fit_transform(df['label_class'].values)
    classes = list(le_class.classes_)
    print(f"[*] Target classes ({len(classes)}): {classes}")

    # Stratified 80/20 train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_class, test_size=0.2, random_state=42, stratify=y_class
    )

    # 1. Random Forest Classifier
    rf_clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=16,
        min_samples_split=3,
        random_state=42,
        n_jobs=-1
    )

    # 2. XGBoost Classifier
    xgb_clf = xgb.XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.85,
        colsample_bytree=0.85,
        objective='multi:softprob',
        eval_metric='mlogloss',
        random_state=42,
        n_jobs=-1
    )

    # 5-Fold Stratified Cross-Validation on training set
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    print("\n[*] Evaluating Random Forest with 5-fold Cross-Validation...")
    rf_cv = cross_validate(rf_clf, X_train, y_train, cv=skf, scoring=['accuracy', 'f1_weighted'])
    print(f"    RF CV Accuracy:  {rf_cv['test_accuracy'].mean():.4f} (+/- {rf_cv['test_accuracy'].std():.4f})")
    print(f"    RF CV F1-Score:  {rf_cv['test_f1_weighted'].mean():.4f}")

    print("\n[*] Evaluating XGBoost with 5-fold Cross-Validation...")
    xgb_cv = cross_validate(xgb_clf, X_train, y_train, cv=skf, scoring=['accuracy', 'f1_weighted'])
    print(f"    XGB CV Accuracy: {xgb_cv['test_accuracy'].mean():.4f} (+/- {xgb_cv['test_accuracy'].std():.4f})")
    print(f"    XGB CV F1-Score: {xgb_cv['test_f1_weighted'].mean():.4f}")

    # Pick champion model
    if xgb_cv['test_accuracy'].mean() >= rf_cv['test_accuracy'].mean():
        champion_model = xgb_clf
        model_name = "XGBoost"
    else:
        champion_model = rf_clf
        model_name = "Random Forest"

    print(f"\n[+] Champion Traffic Model: {model_name}. Fitting on full training split...")
    champion_model.fit(X_train, y_train)

    # Evaluate on held-out 20% test set
    y_pred = champion_model.predict(X_test)
    test_acc = accuracy_score(y_test, y_pred)
    test_f1 = f1_score(y_test, y_pred, average='weighted')

    print(f"\n[RESULTS] Final Test Set Evaluation:")
    print(f"          Test Accuracy: {test_acc * 100:.2f}%")
    print(f"          Weighted F1:   {test_f1:.4f}\n")
    print("Classification Report:")
    report_dict = classification_report(y_test, y_pred, target_names=classes, output_dict=True)
    print(classification_report(y_test, y_pred, target_names=classes))

    cm = confusion_matrix(y_test, y_pred).tolist()

    # Feature importances
    if hasattr(champion_model, 'feature_importances_'):
        importances = champion_model.feature_importances_
        feat_rank = sorted(zip(NUMERIC_FEATURES, importances), key=lambda x: x[1], reverse=True)
        print("\nTop 10 Most Discriminative Features:")
        for rank, (fname, fimp) in enumerate(feat_rank[:10], 1):
            print(f"  {rank:2d}. {fname:20s} : {fimp:.4f}")
    else:
        feat_rank = []

    # Save artifacts
    model_path = os.path.join(output_dir, "traffic_classifier.joblib")
    joblib.dump(champion_model, model_path)
    joblib.dump(le_class, os.path.join(output_dir, "label_encoder_class.joblib"))

    return {
        'model_name': model_name,
        'test_accuracy': test_acc,
        'test_f1_weighted': test_f1,
        'classes': classes,
        'classification_report': report_dict,
        'confusion_matrix': cm,
        'top_features': [{'feature': f, 'importance': float(i)} for f, i in feat_rank[:15]]
    }


def train_mode_classifier(df, X, output_dir):
    """
    Trains Operational Mode Classifier (Tunnel vs Transport).
    """
    print("\n=======================================================")
    print("  TRAINING MODEL 2: OPERATIONAL MODE (TUNNEL VS TRANSPORT)")
    print("=======================================================")

    le_mode = LabelEncoder()
    y_mode = le_mode.fit_transform(df['label_mode'].values)
    modes = list(le_mode.classes_)
    print(f"[*] Target operational modes ({len(modes)}): {modes}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_mode, test_size=0.2, random_state=42, stratify=y_mode
    )

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        random_state=42,
        n_jobs=-1
    )

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_res = cross_validate(clf, X_train, y_train, cv=skf, scoring=['accuracy', 'f1_weighted'])
    print(f"[*] 5-Fold CV Accuracy: {cv_res['test_accuracy'].mean():.4f} (+/- {cv_res['test_accuracy'].std():.4f})")

    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    test_acc = accuracy_score(y_test, y_pred)
    test_f1 = f1_score(y_test, y_pred, average='weighted')

    print(f"\n[RESULTS] Mode Classification Test Accuracy: {test_acc * 100:.2f}% (F1: {test_f1:.4f})")
    print(classification_report(y_test, y_pred, target_names=modes))

    joblib.dump(clf, os.path.join(output_dir, "mode_classifier.joblib"))
    joblib.dump(le_mode, os.path.join(output_dir, "label_encoder_mode.joblib"))

    return {
        'model_name': 'Random Forest',
        'test_accuracy': test_acc,
        'test_f1_weighted': test_f1,
        'classes': modes,
        'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
    }


def main():
    parser = argparse.ArgumentParser(description="SIH26160 AI Model Training Pipeline")
    parser.add_argument("--features", default="dataset/features.csv", help="Path to features.csv")
    parser.add_argument("--output-dir", default="models", help="Directory to save models")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    df, X = load_and_preprocess(args.features)

    # Save feature names schema
    with open(os.path.join(args.output_dir, "feature_columns.json"), "w") as f:
        json.dump(NUMERIC_FEATURES, f, indent=2)

    # Train models
    traffic_metrics = train_traffic_classifier(df, X, args.output_dir)
    mode_metrics = train_mode_classifier(df, X, args.output_dir)

    metrics_summary = {
        'traffic_classifier': traffic_metrics,
        'mode_classifier': mode_metrics,
        'total_dataset_samples': len(df),
        'feature_count': len(NUMERIC_FEATURES)
    }

    metrics_path = os.path.join(args.output_dir, "metrics_summary.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics_summary, f, indent=2)

    print(f"\n[SUCCESS] Model training pipeline finished successfully!")
    print(f"          Models and metrics saved to: {args.output_dir}/")
    print(f"          Traffic Classifier Accuracy: {traffic_metrics['test_accuracy']*100:.2f}%")
    print(f"          Mode Classifier Accuracy:    {mode_metrics['test_accuracy']*100:.2f}%")


if __name__ == "__main__":
    main()
