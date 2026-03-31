#!/usr/bin/env python3
"""Train DeBERTa-v3-base classifier for OCSF — no custom wrapper."""

import json, sys, numpy as np, torch
from collections import Counter
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

DATA = sys.argv[1] if len(sys.argv) > 1 else "data/full_contrastive_training.jsonl"
OUTPUT = sys.argv[2] if len(sys.argv) > 2 else "models/deberta-v8"
EPOCHS = int(sys.argv[3]) if len(sys.argv) > 3 else 15

records = [json.loads(l) for l in open(DATA)]
real = [r for r in records if r.get("source") != "synthetic"]
synth = [r for r in records if r.get("source") == "synthetic"]
all_uids = sorted(set(r["class_uid"] for r in records))
uid_to_idx = {uid: i for i, uid in enumerate(all_uids)}
idx_to_uid = {i: uid for uid, i in uid_to_idx.items()}
num_labels = len(all_uids)
print(f"{len(real)} real, {len(synth)} synth, {num_labels} classes", file=sys.stderr)

real_texts = [r["raw_log"][:512] for r in real]
real_labels = [uid_to_idx[r["class_uid"]] for r in real]
rt, vt, rl, vl = train_test_split(real_texts, real_labels, test_size=0.15, random_state=42, stratify=real_labels)
train_texts = rt + [r["raw_log"][:512] for r in synth]
train_labels = rl + [uid_to_idx[r["class_uid"]] for r in synth]
print(f"Train: {len(train_texts)}, Val: {len(vt)}", file=sys.stderr)

tokenizer = AutoTokenizer.from_pretrained("jackaduma/SecBERT")
model = AutoModelForSequenceClassification.from_pretrained("jackaduma/SecBERT", num_labels=num_labels)

train_enc = tokenizer(train_texts, truncation=True, padding=True, max_length=256)
val_enc = tokenizer(vt, truncation=True, padding=True, max_length=256)

class DS(torch.utils.data.Dataset):
    def __init__(self, enc, labels):
        self.enc, self.labels = enc, labels
    def __getitem__(self, i):
        item = {k: torch.tensor(v[i]) for k, v in self.enc.items()}
        item["labels"] = torch.tensor(self.labels[i])
        return item
    def __len__(self):
        return len(self.labels)

args = TrainingArguments(
    output_dir=f"{OUTPUT}/checkpoints",
    num_train_epochs=EPOCHS,
    per_device_train_batch_size=32,
    per_device_eval_batch_size=64,
    learning_rate=3e-5,
    weight_decay=0.01,
    warmup_ratio=0.06,
    eval_strategy="epoch",
    save_strategy="no",
    load_best_model_at_end=False,
    logging_steps=100,
    seed=42,
    bf16=torch.cuda.is_available() and torch.cuda.is_bf16_supported(),
    fp16=False,
    report_to="none",
)

trainer = Trainer(
    model=model,
    args=args,
    train_dataset=DS(train_enc, train_labels),
    eval_dataset=DS(val_enc, vl),
    compute_metrics=lambda ep: {"accuracy": accuracy_score(ep[1], np.argmax(ep[0], -1))},
)

result = trainer.train()
ev = trainer.evaluate()
print(f"Final accuracy: {ev['eval_accuracy']:.4f}", file=sys.stderr)

out = Path(OUTPUT)
out.mkdir(parents=True, exist_ok=True)
model.save_pretrained(str(out))
tokenizer.save_pretrained(str(out))
json.dump({str(k): v for k, v in idx_to_uid.items()}, open(out / "label_map.json", "w"), indent=2)

uid_to_name = {}
for r in records:
    if r["class_uid"] not in uid_to_name:
        uid_to_name[r["class_uid"]] = r.get("class_name", "")
json.dump({str(k): v for k, v in uid_to_name.items()}, open(out / "class_names.json", "w"), indent=2)
json.dump({"train": result.metrics, "eval": ev, "num_classes": num_labels, "epochs": EPOCHS}, open(out / "training_metrics.json", "w"), indent=2)

# Classification report
preds = trainer.predict(DS(val_enc, vl))
pred_uids = [idx_to_uid[l] for l in np.argmax(preds.predictions, -1)]
true_uids = [idx_to_uid[l] for l in vl]
names = [f"{uid} ({uid_to_name.get(uid, 'unknown')})" for uid in all_uids]
report = classification_report(true_uids, pred_uids, target_names=names, output_dict=True, zero_division=0)
json.dump(report, open(out / "classification_report.json", "w"), indent=2)

print(f"Weighted F1: {report['weighted avg']['f1-score']:.4f}", file=sys.stderr)
below = [(k, v) for k, v in report.items() if isinstance(v, dict) and "f1-score" in v and v["f1-score"] < 0.95 and k not in ("macro avg", "weighted avg")]
below.sort(key=lambda x: x[1]["f1-score"])
for k, v in below[:10]:
    print(f"  {k}: F1={v['f1-score']:.2f} n={int(v['support'])}", file=sys.stderr)
print(f"Model saved to: {OUTPUT}", file=sys.stderr)
