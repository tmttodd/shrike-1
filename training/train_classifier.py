#!/usr/bin/env python3
"""Train DistilBERT classifier for OCSF class classification.

Fine-tunes distilbert-base-uncased on ground truth data for 65-class
OCSF classification. Outputs a model directory with:
  - model.safetensors (weights)
  - tokenizer files
  - label_map.json (model index → class_uid)
  - training_metrics.json (accuracy, loss, etc.)

Usage:
    python scripts/train_classifier.py \
        --ground-truth data/ground_truth/classification_ground_truth.jsonl \
        --output models/distilbert-ocsf-classifier \
        --epochs 5 \
        --batch-size 32

Requires: pip install torch transformers scikit-learn
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np


def main():
    parser = argparse.ArgumentParser(description="Train DistilBERT OCSF classifier")
    parser.add_argument("--ground-truth", required=True, help="Ground truth JSONL")
    parser.add_argument("--output", required=True, help="Output model directory")
    parser.add_argument("--epochs", type=int, default=5, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size")
    parser.add_argument("--lr", type=float, default=2e-5, help="Learning rate")
    parser.add_argument("--max-length", type=int, default=256, help="Max token length")
    parser.add_argument("--val-split", type=float, default=0.15, help="Validation split")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--model-name", default="distilbert-base-uncased", help="Base model")
    args = parser.parse_args()

    import torch
    from transformers import (
        AutoTokenizer,
        AutoModelForSequenceClassification,
        TrainingArguments,
        Trainer,
    )
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report

    # Load data
    print("Loading ground truth...", file=sys.stderr)
    records = []
    with open(args.ground_truth) as f:
        for line in f:
            d = json.loads(line)
            records.append({
                "text": d["raw_log"][:512],
                "class_uid": d["class_uid"],
                "class_name": d.get("class_name", ""),
            })

    # Build label mapping
    unique_uids = sorted(set(r["class_uid"] for r in records))
    uid_to_idx = {uid: idx for idx, uid in enumerate(unique_uids)}
    idx_to_uid = {idx: uid for uid, idx in uid_to_idx.items()}
    num_labels = len(unique_uids)

    print(f"Loaded {len(records)} records, {num_labels} classes", file=sys.stderr)

    # Class distribution — drop classes with too few samples for stratified split
    uid_counts = Counter(r["class_uid"] for r in records)
    min_samples = max(3, int(1 / args.val_split) + 1)  # Need at least this many for stratified split
    small_classes = {uid for uid, count in uid_counts.items() if count < min_samples}
    if small_classes:
        print(f"Dropping {len(small_classes)} classes with <{min_samples} samples: {sorted(small_classes)}", file=sys.stderr)
        records = [r for r in records if r["class_uid"] not in small_classes]
        # Rebuild label mapping
        unique_uids = sorted(set(r["class_uid"] for r in records))
        uid_to_idx = {uid: idx for idx, uid in enumerate(unique_uids)}
        idx_to_uid = {idx: uid for uid, idx in uid_to_idx.items()}
        num_labels = len(unique_uids)
        uid_counts = Counter(r["class_uid"] for r in records)

    print(f"Training on {len(records)} records, {num_labels} classes", file=sys.stderr)
    print(f"Min class size: {min(uid_counts.values())}, Max: {max(uid_counts.values())}", file=sys.stderr)

    # Stratified split
    texts = [r["text"] for r in records]
    labels = [uid_to_idx[r["class_uid"]] for r in records]

    train_texts, val_texts, train_labels, val_labels = train_test_split(
        texts, labels, test_size=args.val_split, random_state=args.seed, stratify=labels
    )
    print(f"Train: {len(train_texts)}, Val: {len(val_texts)}", file=sys.stderr)

    # Tokenize
    print(f"Loading tokenizer from {args.model_name}...", file=sys.stderr)
    tokenizer = AutoTokenizer.from_pretrained(args.model_name)

    train_encodings = tokenizer(train_texts, truncation=True, padding=True, max_length=args.max_length)
    val_encodings = tokenizer(val_texts, truncation=True, padding=True, max_length=args.max_length)

    # Dataset
    class LogDataset(torch.utils.data.Dataset):
        def __init__(self, encodings, labels):
            self.encodings = encodings
            self.labels = labels

        def __getitem__(self, idx):
            item = {k: torch.tensor(v[idx]) for k, v in self.encodings.items()}
            item["labels"] = torch.tensor(self.labels[idx])
            return item

        def __len__(self):
            return len(self.labels)

    train_dataset = LogDataset(train_encodings, train_labels)
    val_dataset = LogDataset(val_encodings, val_labels)

    # Model
    print(f"Loading model {args.model_name} ({num_labels} labels)...", file=sys.stderr)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model_name, num_labels=num_labels
    )

    # Training args
    output_dir = Path(args.output)
    training_args = TrainingArguments(
        output_dir=str(output_dir / "checkpoints"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size * 2,
        learning_rate=args.lr,
        weight_decay=0.01,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="accuracy",
        logging_steps=50,
        seed=args.seed,
        fp16=torch.cuda.is_available(),
        report_to="none",
    )

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        predictions = np.argmax(logits, axis=-1)
        acc = accuracy_score(labels, predictions)
        return {"accuracy": acc}

    # Train
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
    )

    print("Starting training...", file=sys.stderr)
    result = trainer.train()
    print(f"Training complete: {result.metrics}", file=sys.stderr)

    # Evaluate
    eval_result = trainer.evaluate()
    print(f"Eval metrics: {eval_result}", file=sys.stderr)

    # Save model
    output_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))

    # Save label mapping
    with open(output_dir / "label_map.json", "w") as f:
        json.dump({str(k): v for k, v in idx_to_uid.items()}, f, indent=2)

    # Save class name mapping
    uid_to_name = {}
    for r in records:
        if r["class_uid"] not in uid_to_name and r.get("class_name"):
            uid_to_name[r["class_uid"]] = r["class_name"]
    with open(output_dir / "class_names.json", "w") as f:
        json.dump({str(k): v for k, v in uid_to_name.items()}, f, indent=2)

    # Save training metrics
    metrics = {
        "train": result.metrics,
        "eval": eval_result,
        "num_classes": num_labels,
        "num_records": len(records),
        "epochs": args.epochs,
        "model_name": args.model_name,
    }
    with open(output_dir / "training_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    # Full classification report on val set
    val_preds = trainer.predict(val_dataset)
    pred_labels = np.argmax(val_preds.predictions, axis=-1)
    true_uids = [idx_to_uid[l] for l in val_labels]
    pred_uids = [idx_to_uid[l] for l in pred_labels]

    report = classification_report(
        true_uids, pred_uids,
        target_names=[f"{uid} ({uid_to_name.get(uid, '?')})" for uid in unique_uids],
        output_dict=True,
    )
    with open(output_dir / "classification_report.json", "w") as f:
        json.dump(report, f, indent=2)

    acc = report.get("accuracy", report.get("weighted avg", {}).get("f1-score", 0))
    print(f"\nFinal accuracy: {acc:.4f}", file=sys.stderr)
    print(f"Model saved to: {output_dir}", file=sys.stderr)


if __name__ == "__main__":
    main()
