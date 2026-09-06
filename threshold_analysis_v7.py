# -*- coding: utf-8 -*-
"""
threshold_analysis_v7.py

목적: v7 모델(구어체 보강 재학습) 기준 ROC/PR 곡선 재분석
- 입력 1: test_predictions_v7.csv   (v7 재학습 시 생성된 정식 Test셋 예측 결과, 45건)
- 입력 2: eval_v7_full_results.csv  (하드케이스 84건: 격식체 50건 + 신규 구어체 34건 예측 결과)
  -> 둘을 병합(중복 제거)한 129건 기준으로 분석

출력:
- threshold_analysis_v7.png (ROC curve + PR curve, 후보 threshold 표시)
- threshold_candidates_v7.csv (여러 기준별 후보 threshold와 성능 비교표)

실행 환경: Colab (train_koelectra_v7.py, eval_v7_full.py와 같은 폴더)

최종 채택값: BLOCK_THRESHOLD = 0.41, REVIEW_THRESHOLD = 0.20
근거: Youden's J / F1-optimal / F2-optimal(Recall 가중) 세 기준이 공통으로
      threshold ~0.41 부근에 수렴(AUC 0.9949). REVIEW 하한은 review/allow
      경계를 스윕한 결과, 0.20에서 비기밀 allow율의 추가 손실 없이 기밀
      recall이 개선되는 지점으로 확인(0.44/0.30 대비 개선).
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import (
    roc_curve, auc, precision_recall_curve, fbeta_score,
    precision_score, recall_score, f1_score
)

TEST_PRED_PATH = "test_predictions_v7.csv"
HARD_PRED_PATH = "eval_v7_full_results.csv"
CURRENT_BLOCK = 0.44
CURRENT_REVIEW = 0.30
OUTPUT_PNG = "threshold_analysis_v7.png"
OUTPUT_CSV = "threshold_candidates_v7.csv"

test_df = pd.read_csv(TEST_PRED_PATH)[["text", "label", "prob_sensitive"]]
hard_df = pd.read_csv(HARD_PRED_PATH)[["text", "label", "prob_sensitive"]]

combined = pd.concat([test_df, hard_df], ignore_index=True)
combined = combined.drop_duplicates(subset=["text"]).reset_index(drop=True)

y_true = combined["label"].values
y_prob = combined["prob_sensitive"].values

print(f"[INFO] 정식 Test셋: {len(test_df)}건 / 하드케이스(격식체+구어체): {len(hard_df)}건")
print(f"[INFO] 병합(중복 제거) 후 전체 평가셋: {len(combined)}건 "
      f"(label 분포: {combined['label'].value_counts().to_dict()})")

# ---------------- ROC + Youden's J ----------------
fpr, tpr, roc_thresholds = roc_curve(y_true, y_prob)
roc_auc = auc(fpr, tpr)
youden_j = tpr - fpr
best_j_idx = np.argmax(youden_j)
best_j_threshold = roc_thresholds[best_j_idx]

print(f"\n[ROC] AUC = {roc_auc:.4f}")
print(f"[ROC] Youden's J 최적 threshold = {best_j_threshold:.4f} "
      f"(TPR={tpr[best_j_idx]:.3f}, FPR={fpr[best_j_idx]:.3f})")

# ---------------- PR + F1 / F2 ----------------
precisions, recalls, pr_thresholds = precision_recall_curve(y_true, y_prob)
f1_scores = 2 * (precisions[:-1] * recalls[:-1]) / (precisions[:-1] + recalls[:-1] + 1e-9)
best_f1_idx = np.argmax(f1_scores)
best_f1_threshold = pr_thresholds[best_f1_idx]

beta = 2
f2_scores = (1 + beta**2) * (precisions[:-1] * recalls[:-1]) / (
    (beta**2 * precisions[:-1]) + recalls[:-1] + 1e-9
)
best_f2_idx = np.argmax(f2_scores)
best_f2_threshold = pr_thresholds[best_f2_idx]

print(f"\n[PR] F1 최적 threshold = {best_f1_threshold:.4f} "
      f"(P={precisions[best_f1_idx]:.3f}, R={recalls[best_f1_idx]:.3f})")
print(f"[PR] F2 최적 threshold = {best_f2_threshold:.4f} "
      f"(P={precisions[best_f2_idx]:.3f}, R={recalls[best_f2_idx]:.3f})")

# ---------------- BLOCK 후보 비교표 ----------------
def eval_at(th):
    pred = (y_prob >= th).astype(int)
    return {
        "threshold": round(th, 4),
        "precision": round(precision_score(y_true, pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, pred, zero_division=0), 4),
        "f2": round(fbeta_score(y_true, pred, beta=2, zero_division=0), 4),
    }

candidates = pd.DataFrame([
    {"criterion": f"기존 BLOCK 값 ({CURRENT_BLOCK})", **eval_at(CURRENT_BLOCK)},
    {"criterion": "Youden's J (ROC 최적)", **eval_at(best_j_threshold)},
    {"criterion": "F1 최적 (PR curve)", **eval_at(best_f1_threshold)},
    {"criterion": "F2 최적 (Recall 가중, DLP 권장)", **eval_at(best_f2_threshold)},
])
print("\n=== BLOCK Threshold 후보 비교표 ===")
print(candidates.to_string(index=False))
candidates.to_csv(OUTPUT_CSV, index=False, encoding="utf-8-sig")

# ---------------- REVIEW 후보 스윕 ----------------
label0 = combined[combined["label"] == 0]
label1 = combined[combined["label"] == 1]

print("\n=== REVIEW Threshold 후보별 실제 분류 결과 (BLOCK은 채택값 0.41 기준) ===")
block_th = 0.41
for th in [0.15, 0.20, 0.25, 0.30, 0.33, 0.35, 0.40]:
    allow_cnt = (label0["prob_sensitive"] < th).sum()
    review_cnt = ((label0["prob_sensitive"] >= th) & (label0["prob_sensitive"] < block_th)).sum()
    fp_block_cnt = (label0["prob_sensitive"] >= block_th).sum()
    fn_cnt = (label1["prob_sensitive"] < th).sum()
    print(f"th={th:.2f} | 비기밀 allow={allow_cnt}/{len(label0)} ({allow_cnt/len(label0)*100:.1f}%) "
          f"review={review_cnt} block={fp_block_cnt} | 기밀 놓침(allow)={fn_cnt}")

# ---------------- 시각화 ----------------
fig, axes = plt.subplots(1, 2, figsize=(13, 5.5))

ax = axes[0]
ax.plot(fpr, tpr, label=f"ROC curve (AUC={roc_auc:.3f})", linewidth=2)
ax.plot([0, 1], [0, 1], linestyle="--", color="gray", label="Random")
ax.scatter(fpr[best_j_idx], tpr[best_j_idx], color="red", zorder=5,
           label=f"Youden's J opt (th={best_j_threshold:.2f})")
ax.set_xlabel("False Positive Rate")
ax.set_ylabel("True Positive Rate")
ax.set_title("ROC Curve (v7)")
ax.legend(loc="lower right", fontsize=9)
ax.grid(alpha=0.3)

ax = axes[1]
ax.plot(recalls, precisions, label="PR curve", linewidth=2, color="tab:orange")
ax.scatter(recalls[best_f1_idx], precisions[best_f1_idx], color="red", zorder=5,
           label=f"F1 opt (th={best_f1_threshold:.2f})")
ax.scatter(recalls[best_f2_idx], precisions[best_f2_idx], color="green", zorder=5,
           label=f"F2 opt (th={best_f2_threshold:.2f})")
ax.set_xlabel("Recall")
ax.set_ylabel("Precision")
ax.set_title("Precision-Recall Curve (v7)")
ax.legend(loc="lower left", fontsize=9)
ax.grid(alpha=0.3)

plt.tight_layout()
plt.savefig(OUTPUT_PNG, dpi=150)
print(f"\n[INFO] 그래프 저장: {OUTPUT_PNG}")
