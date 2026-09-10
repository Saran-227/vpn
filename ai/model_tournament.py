#!/usr/bin/env python3
"""
SIH26160 IPsec Traffic Analysis - Model Tournament & Ensemble Optimization
Benchmarks diverse model families (Bagging, Boosting, Neural Nets, Voting & Stacking Ensembles)
across 5-Fold Stratified Cross-Validation on the 48-feature dataset.
Selects the champion architecture and saves it for production inference.
"""

import os
import sys
import json
import time
import argparse
import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import StratifiedKFold, train_test_split, cross_validate
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix
from sklearn.ensemble import (
    RandomForestClassifier,
    ExtraTreesClassifier,
    HistGradientBoostingClassifier,
    VotingClassifier,
    StackingClassifier
)
from sklearn.neural_network import MLPClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

import xgboost as xgb
import lightgbm as lgb
from catboost import CatBoostClassifier

from features.extractor import NUMERIC_FEATURES


def load_dataset(csv_path):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Features file not found: {csv_path}")

    df = pd.read_csv(csv_path)
    print(f"[*] Loaded dataset: {len(df)} samples, {len(NUMERIC_FEATURES)} features")

    # Clean numeric features
    for col in NUMERIC_FEATURES:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)
            df[col] = df[col].replace([np.inf, -np.inf], 0.0)
        else:
            df[col] = 0.0

    X = df[NUMERIC_FEATURES].values
    le = LabelEncoder()
    y = le.fit_transform(df['label_class'].values)
    classes = list(le.classes_)

    return df, X, y, le, classes


def build_candidate_models():
    """
    Builds a diverse pool of candidate classifiers.
    """
    candidates = {}

    # 1. Random Forest (Bagging)
    candidates["Random Forest (Bagging)"] = RandomForestClassifier(
        n_estimators=250,
        max_depth=18,
        min_samples_split=3,
        max_features='sqrt',
        random_state=42,
        n_jobs=-1
    )

    # 2. Extra Trees (Extreme Variance Reduction Bagging)
    candidates["Extra Trees (Bagging)"] = ExtraTreesClassifier(
        n_estimators=250,
        max_depth=20,
        min_samples_split=2,
        max_features='sqrt',
        random_state=42,
        n_jobs=-1
    )

    # 3. XGBoost (Gradient Tree Boosting)
    candidates["XGBoost (Boosting)"] = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.80,
        min_child_weight=2,
        objective='multi:softprob',
        eval_metric='mlogloss',
        random_state=42,
        n_jobs=-1
    )

    # 4. LightGBM (Histogram-based Fast Boosting)
    candidates["LightGBM (Boosting)"] = lgb.LGBMClassifier(
        n_estimators=200,
        num_leaves=31,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.80,
        random_state=42,
        n_jobs=-1,
        verbose=-1
    )

    # 5. CatBoost (Oblivious Trees Boosting)
    candidates["CatBoost (Boosting)"] = CatBoostClassifier(
        iterations=250,
        depth=6,
        learning_rate=0.08,
        random_seed=42,
        verbose=0,
        thread_count=-1
    )

    # 6. HistGradientBoosting (Scikit-learn native)
    candidates["HistGradientBoosting"] = HistGradientBoostingClassifier(
        max_iter=150,
        max_leaf_nodes=31,
        learning_rate=0.08,
        random_state=42
    )

    # 7. Multi-Layer Perceptron (Neural Network)
    candidates["Multi-Layer Perceptron (MLP)"] = make_pipeline(
        StandardScaler(),
        MLPClassifier(
            hidden_layer_sizes=(128, 64),
            activation='relu',
            alpha=0.001,
            max_iter=300,
            random_state=42,
            early_stopping=True
        )
    )

    return candidates


def run_tournament(X, y, classes, output_dir="models"):
    print("\n" + "="*75)
    print("      SIH26160 AI MODEL TOURNAMENT & ENSEMBLE BENCHMARK")
    print("="*75)
    print(f"Features: {X.shape[1]} | Samples: {X.shape[0]} | Classes: {len(classes)} {classes}\n")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    candidates = build_candidate_models()
    leaderboard = []

    fitted_models = {}

    for name, model in candidates.items():
        print(f"[*] Benchmarking: {name:30s} ... ", end="", flush=True)
        t0 = time.time()
        cv_res = cross_validate(model, X_train, y_train, cv=skf, scoring=['accuracy', 'f1_weighted'])
        elapsed = time.time() - t0

        cv_acc = cv_res['test_accuracy'].mean()
        cv_acc_std = cv_res['test_accuracy'].std()
        cv_f1 = cv_res['test_f1_weighted'].mean()

        # Fit on full training set and evaluate on test set
        model.fit(X_train, y_train)
        fitted_models[name] = model
        y_pred = model.predict(X_test)
        test_acc = accuracy_score(y_test, y_pred)
        test_f1 = f1_score(y_test, y_pred, average='weighted')

        print(f"CV Acc: {cv_acc*100:5.2f}% (+/- {cv_acc_std*100:4.2f}%) | Test Acc: {test_acc*100:5.2f}% | Time: {elapsed:4.1f}s")

        leaderboard.append({
            "model_name": name,
            "cv_accuracy": round(float(cv_acc), 4),
            "cv_acc_std": round(float(cv_acc_std), 4),
            "cv_f1": round(float(cv_f1), 4),
            "test_accuracy": round(float(test_acc), 4),
            "test_f1": round(float(test_f1), 4),
            "train_time_sec": round(elapsed, 2)
        })

    # -------------------------------------------------------------
    # Now build HYBRID ENSEMBLES (Voting & Stacking)
    # -------------------------------------------------------------
    print("\n[*] Building Advanced Ensembles (Combining Top Bagging & Boosting Models)...")

    # Pick top 4 distinct models from leaderboard
    sorted_candidates = sorted(leaderboard, key=lambda x: x['cv_accuracy'], reverse=True)
    top_names = [x['model_name'] for x in sorted_candidates[:4]]
    print(f"    Selected Base Estimators for Ensemble: {top_names}")

    # Build soft-voting ensemble
    voting_estimators = [(name.split()[0].lower(), candidates[name]) for name in top_names if name in candidates]
    voting_ensemble = VotingClassifier(estimators=voting_estimators, voting='soft', n_jobs=-1)

    print("[*] Benchmarking: Soft Voting Ensemble           ... ", end="", flush=True)
    t0 = time.time()
    cv_res = cross_validate(voting_ensemble, X_train, y_train, cv=skf, scoring=['accuracy', 'f1_weighted'])
    elapsed = time.time() - t0
    cv_acc = cv_res['test_accuracy'].mean()
    cv_f1 = cv_res['test_f1_weighted'].mean()
    voting_ensemble.fit(X_train, y_train)
    fitted_models["Soft Voting Ensemble"] = voting_ensemble
    y_pred = voting_ensemble.predict(X_test)
    test_acc = accuracy_score(y_test, y_pred)
    test_f1 = f1_score(y_test, y_pred, average='weighted')
    print(f"CV Acc: {cv_acc*100:5.2f}% | Test Acc: {test_acc*100:5.2f}% | Time: {elapsed:4.1f}s")

    leaderboard.append({
        "model_name": "Soft Voting Ensemble",
        "cv_accuracy": round(float(cv_acc), 4),
        "cv_acc_std": round(float(cv_res['test_accuracy'].std()), 4),
        "cv_f1": round(float(cv_f1), 4),
        "test_accuracy": round(float(test_acc), 4),
        "test_f1": round(float(test_f1), 4),
        "train_time_sec": round(elapsed, 2)
    })

    # Build stacking ensemble with LogisticRegression meta-learner
    stacking_ensemble = StackingClassifier(
        estimators=voting_estimators,
        final_estimator=LogisticRegression(max_iter=500, C=1.0, random_state=42),
        cv=skf,
        n_jobs=-1
    )

    print("[*] Benchmarking: Stacking Ensemble              ... ", end="", flush=True)
    t0 = time.time()
    cv_res = cross_validate(stacking_ensemble, X_train, y_train, cv=skf, scoring=['accuracy', 'f1_weighted'])
    elapsed = time.time() - t0
    cv_acc = cv_res['test_accuracy'].mean()
    cv_f1 = cv_res['test_f1_weighted'].mean()
    stacking_ensemble.fit(X_train, y_train)
    fitted_models["Stacking Ensemble"] = stacking_ensemble
    y_pred = stacking_ensemble.predict(X_test)
    test_acc = accuracy_score(y_test, y_pred)
    test_f1 = f1_score(y_test, y_pred, average='weighted')
    print(f"CV Acc: {cv_acc*100:5.2f}% | Test Acc: {test_acc*100:5.2f}% | Time: {elapsed:4.1f}s")

    leaderboard.append({
        "model_name": "Stacking Ensemble",
        "cv_accuracy": round(float(cv_acc), 4),
        "cv_acc_std": round(float(cv_res['test_accuracy'].std()), 4),
        "cv_f1": round(float(cv_f1), 4),
        "test_accuracy": round(float(test_acc), 4),
        "test_f1": round(float(test_f1), 4),
        "train_time_sec": round(elapsed, 2)
    })

    # Final Leaderboard Ranking (ranked by Test Accuracy and CV Accuracy)
    final_ranked = sorted(leaderboard, key=lambda x: (x['test_accuracy'], x['cv_accuracy']), reverse=True)

    print("\n" + "="*85)
    print(f"{'RANK':4s} | {'MODEL ARCHITECTURE':32s} | {'CV ACCURACY':12s} | {'TEST ACCURACY':13s} | {'TEST F1':8s}")
    print("="*85)
    for rank, entry in enumerate(final_ranked, 1):
        crown = " (CHAMPION)" if rank == 1 else ""
        print(f"{rank:4d} | {entry['model_name']:32s} | {entry['cv_accuracy']*100:6.2f}%     | {entry['test_accuracy']*100:6.2f}%{crown:11s} | {entry['test_f1']:6.4f}")
    print("="*85 + "\n")

    champion_entry = final_ranked[0]
    champion_name = champion_entry['model_name']
    champion_model = fitted_models[champion_name]

    print(f"[+] Champion Model Selected: {champion_name}")
    print(f"    Held-Out Test Accuracy: {champion_entry['test_accuracy']*100:.2f}%")
    print(f"    Held-Out Weighted F1:   {champion_entry['test_f1']:.4f}\n")

    # Detailed report for champion
    y_pred_champ = champion_model.predict(X_test)
    print("Champion Classification Report:")
    report_dict = classification_report(y_test, y_pred_champ, target_names=classes, output_dict=True)
    print(classification_report(y_test, y_pred_champ, target_names=classes))

    # Save champion model to disk
    os.makedirs(output_dir, exist_ok=True)
    champ_path = os.path.join(output_dir, "traffic_classifier.joblib")
    joblib.dump(champion_model, champ_path)
    print(f"[SUCCESS] Champion model exported to: {champ_path}")

    # Save feature names and tournament leaderboard
    with open(os.path.join(output_dir, "feature_columns.json"), "w") as f:
        json.dump(NUMERIC_FEATURES, f, indent=2)

    with open(os.path.join(output_dir, "tournament_leaderboard.json"), "w") as f:
        json.dump({
            "leaderboard": final_ranked,
            "champion": champion_name,
            "test_accuracy": champion_entry['test_accuracy'],
            "test_f1": champion_entry['test_f1'],
            "classification_report": report_dict,
            "confusion_matrix": confusion_matrix(y_test, y_pred_champ).tolist(),
            "classes": classes
        }, f, indent=2)

    return champion_model, final_ranked


def main():
    parser = argparse.ArgumentParser(description="SIH26160 AI Model Tournament")
    parser.add_argument("--features", default="dataset/features.csv", help="Path to features.csv")
    parser.add_argument("--output-dir", default="models", help="Output directory")
    args = parser.parse_args()

    df, X, y, le, classes = load_dataset(args.features)
    # Save label encoder
    joblib.dump(le, os.path.join(args.output_dir, "label_encoder_class.joblib"))

    run_tournament(X, y, classes, output_dir=args.output_dir)


if __name__ == "__main__":
    main()
