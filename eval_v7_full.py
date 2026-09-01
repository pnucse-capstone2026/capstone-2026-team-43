# -*- coding: utf-8 -*-
"""
eval_v7_full.py

목적: koelectra-dlp-v7 모델을 아래 두 세트로 검증
1) hard_test_set_v1.csv    (기존 격식체 하드케이스 50건) -> 퇴보 여부 확인
2) hard_test_casual_v2.csv (신규 구어체 34건, 학습에 전혀 안 쓴 새 문장) -> 진짜 일반화 확인

실행 환경: Colab (koelectra-dlp-v7/final 이 같은 폴더 기준 상대경로에 있어야 함)
"""

import pandas as pd
import numpy as np
import torch
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
from transformers import AutoTokenizer, AutoModelForSequenceClassification

MODEL_DIR = "./koelectra-dlp-v7/final"
BLOCK_THRESHOLD = 0.44
REVIEW_THRESHOLD = 0.30
MAX_LENGTH = 128

device = "cuda" if torch.cuda.is_available() else "cpu"

tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR).to(device)
model.eval()

def load_and_tag(path, source):
    df = pd.read_csv(path)
    df["source"] = source
    return df

df1 = load_and_tag("hard_test_set_v1.csv", "formal_hard_v1")
df2 = load_and_tag("hard_test_casual_v2.csv", "casual_new_v2")

combined = pd.concat([df1, df2], ignore_index=True)
print(f"[INFO] 평가셋: 격식체 하드케이스 {len(df1)}건 + 신규 구어체 {len(df2)}건 = 총 {len(combined)}건")

def predict(texts):
    enc = tokenizer(texts, padding=True, truncation=True, max_length=MAX_LENGTH, return_tensors="pt").to(device)
    with torch.no_grad():
        logits = model(**enc).logits
    return torch.softmax(logits, dim=1)[:, 1].cpu().numpy()

probs = predict(combined["text"].tolist())
combined["prob_sensitive"] = probs

def to_decision(p):
    if p >= BLOCK_THRESHOLD:
        return "block"
    elif p >= REVIEW_THRESHOLD:
        return "review"
    return "allow"

combined["decision"] = combined["prob_sensitive"].apply(to_decision)
combined["pred"] = (combined["prob_sensitive"] >= BLOCK_THRESHOLD).astype(int)  # 기존 이진 정확도 계산용
combined["correct"] = (combined["pred"] == combined["label"]) | (
    (combined["label"] == 0) & (combined["decision"] != "block")
)  # 비기밀은 block만 아니면 "정답"으로 관대하게 채점 (review도 안전 범위로 인정)

print("\n=== 전체 정확도 (엄격: block 기준 이진) ===")
print(f"{accuracy_score(combined['label'], combined['pred']):.4f}")

print("\n=== source별 성능 ===")
for src in combined["source"].unique():
    sub = combined[combined["source"] == src]
    sub1 = sub[sub["label"] == 1]
    sub0 = sub[sub["label"] == 0]
    recall_1 = (sub1["decision"] != "allow").mean() if len(sub1) else float("nan")  # block/review로 걸러짐
    fp_block_0 = (sub0["decision"] == "block").mean() if len(sub0) else float("nan")
    allow_0 = (sub0["decision"] == "allow").mean() if len(sub0) else float("nan")
    print(f"\n[{src}] (n={len(sub)}, 기밀={len(sub1)}, 비기밀={len(sub0)})")
    print(f"  기밀 recall(block/review로 걸러짐): {recall_1*100:.1f}%")
    print(f"  비기밀 allow 비율:                  {allow_0*100:.1f}%")
    print(f"  비기밀 오탐(block):                 {fp_block_0*100:.1f}%")

print("\n=== 오답(기밀인데 allow로 샌 경우) 상세 ===")
missed = combined[(combined["label"] == 1) & (combined["decision"] == "allow")]
if len(missed) == 0:
    print("없음 - 기밀은 전부 block/review로 걸러짐")
else:
    for _, row in missed.iterrows():
        print(f"  [{row['source']}] prob={row['prob_sensitive']:.3f} | {row['text']}")

print("\n=== 오탐(비기밀인데 block) 상세 ===")
false_block = combined[(combined["label"] == 0) & (combined["decision"] == "block")]
if len(false_block) == 0:
    print("없음")
else:
    for _, row in false_block.iterrows():
        print(f"  [{row['source']}] prob={row['prob_sensitive']:.3f} | {row['text']}")

combined.to_csv("eval_v7_full_results.csv", index=False, encoding="utf-8-sig")
print("\n[INFO] 상세 결과 저장: eval_v7_full_results.csv")
