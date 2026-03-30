#!/usr/bin/env python3
"""Train DistilBERT OCSF classifier — Phase 1 optimized.

Key changes from train_classifier.py:
  - Class-weighted loss (inverse frequency weighting)
  - Real-only validation (synthetic only in train)
  - 10 epochs (v1 was still improving at epoch 5)
  - Warmup schedule for stable training
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import torch
from torch import nn


def main():
    parser = argparse.ArgumentParser(description="Train DistilBERT OCSF classifier (v4)")
    parser.add_argument("--training-data", required=True, help="Balanced training JSONL")
    parser.add_argument("--output", required=True, help="Output model directory")
    parser.add_argument("--epochs", type=int, default=10, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size")
    parser.add_argument("--lr", type=float, default=2e-5, help="Learning rate")
    parser.add_argument("--max-length", type=int, default=256, help="Max token length")
    parser.add_argument("--val-split", type=float, default=0.15, help="Validation split")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--model-name", default="distilbert-base-uncased", help="Base model")
    parser.add_argument("--warmup-ratio", type=float, default=0.1, help="Warmup ratio")
    args = parser.parse_args()

    from transformers import (
        AutoTokenizer,
        AutoModelForSequenceClassification,
        TrainingArguments,
        Trainer,
    )
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report

    # Load data
    print("Loading training data...", file=sys.stderr)
    records = []
    with open(args.training_data) as f:
        for line in f:
            records.append(json.loads(line))

    # Separate real and synthetic
    real_records = [r for r in records if r.get("source") != "synthetic"]
    synth_records = [r for r in records if r.get("source") == "synthetic"]
    print(f"  Real: {len(real_records)}, Synthetic: {len(synth_records)}", file=sys.stderr)

    # Build label mapping from ALL data
    all_uids = sorted(set(r["class_uid"] for r in records))
    uid_to_idx = {uid: idx for idx, uid in enumerate(all_uids)}
    idx_to_uid = {idx: uid for uid, idx in uid_to_idx.items()}
    num_labels = len(all_uids)
    print(f"  {num_labels} classes", file=sys.stderr)

    # Split REAL data only for validation — synthetic stays in training
    real_texts = [r["raw_log"][:512] for r in real_records]
    real_labels = [uid_to_idx[r["class_uid"]] for r in real_records]

    # Stratified split on real data
    real_train_texts, val_texts, real_train_labels, val_labels = train_test_split(
        real_texts, real_labels, test_size=args.val_split,
        random_state=args.seed, stratify=real_labels,
    )

    # Add synthetic to training only
    synth_texts = [r["raw_log"][:512] for r in synth_records]
    synth_labels = [uid_to_idx[r["class_uid"]] for r in synth_records]
    train_texts = real_train_texts + synth_texts
    train_labels = real_train_labels + synth_labels

    print(f"  Train: {len(train_texts)} (real: {len(real_train_texts)}, synth: {len(synth_texts)})", file=sys.stderr)
    print(f"  Val: {len(val_texts)} (real only)", file=sys.stderr)

    # Compute class weights (inverse frequency)
    train_counts = Counter(train_labels)
    total_train = len(train_labels)
    class_weights = torch.zeros(num_labels)
    for idx in range(num_labels):
        count = train_counts.get(idx, 1)
        # Inverse frequency with smoothing
        class_weights[idx] = total_train / (num_labels * count)
    # Normalize so mean weight = 1.0
    class_weights = class_weights / class_weights.mean()
    print(f"  Class weight range: {class_weights.min():.2f} - {class_weights.max():.2f}", file=sys.stderr)

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

    # Model with weighted loss
    print(f"Loading model {args.model_name} ({num_labels} labels)...", file=sys.stderr)

    class WeightedDistilBERT(nn.Module):
        def __init__(self, model_name, num_labels, class_weights):
            super().__init__()
            self.model = AutoModelForSequenceClassification.from_pretrained(
                model_name, num_labels=num_labels
            )
            self.class_weights = class_weights
            self.num_labels = num_labels

        def forward(self, input_ids=None, attention_mask=None, labels=None, **kwargs):
            outputs = self.model(input_ids=input_ids, attention_mask=attention_mask, labels=None)
            logits = outputs.logits

            loss = None
            if labels is not None:
                weight = self.class_weights.to(logits.device)
                loss_fn = nn.CrossEntropyLoss(weight=weight)
                loss = loss_fn(logits, labels)

            return type(outputs)(loss=loss, logits=logits, hidden_states=outputs.hidden_states, attentions=outputs.attentions)

        @property
        def config(self):
            return self.model.config

        def save_pretrained(self, path):
            self.model.save_pretrained(path)

        @property
        def device(self):
            return next(self.parameters()).device

    model = WeightedDistilBERT(args.model_name, num_labels, class_weights)

    # Training args
    output_dir = Path(args.output)
    training_args = TrainingArguments(
        output_dir=str(output_dir / "checkpoints"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size * 2,
        learning_rate=args.lr,
        weight_decay=0.01,
        warmup_ratio=args.warmup_ratio,
        eval_strategy="epoch",
        save_strategy="no",
        load_best_model_at_end=False,
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

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
    )

    print("Starting training...", file=sys.stderr)
    result = trainer.train()
    print(f"Training complete: loss={result.metrics['train_loss']:.4f}", file=sys.stderr)

    # Evaluate
    eval_result = trainer.evaluate()
    print(f"Eval accuracy: {eval_result['eval_accuracy']:.4f}", file=sys.stderr)

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
        "num_train": len(train_texts),
        "num_val": len(val_texts),
        "num_real_train": len(real_train_texts),
        "num_synth_train": len(synth_texts),
        "epochs": args.epochs,
        "model_name": args.model_name,
        "class_weight_range": [float(class_weights.min()), float(class_weights.max())],
    }
    with open(output_dir / "training_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    # Full classification report on validation set (real only)
    val_preds = trainer.predict(val_dataset)
    pred_labels = np.argmax(val_preds.predictions, axis=-1)
    true_uids = [idx_to_uid[l] for l in val_labels]
    pred_uids = [idx_to_uid[l] for l in pred_labels]

    report = classification_report(
        true_uids, pred_uids,
        target_names=[f"{uid} ({uid_to_name.get(uid, '?')})" for uid in all_uids],
        output_dict=True,
        zero_division=0,
    )
    with open(output_dir / "classification_report.json", "w") as f:
        json.dump(report, f, indent=2)

    acc = eval_result["eval_accuracy"]
    print(f"\nFinal accuracy: {acc:.4f}", file=sys.stderr)
    print(f"Model saved to: {output_dir}", file=sys.stderr)

    # Print per-class summary
    print(f"\nPer-class F1 (sorted):", file=sys.stderr)
    class_items = [(k, v) for k, v in report.items()
                   if isinstance(v, dict) and "f1-score" in v
                   and k not in ("macro avg", "weighted avg")]
    class_items.sort(key=lambda x: x[1]["f1-score"])
    for k, v in class_items[:10]:
        print(f"  {k}: F1={v['f1-score']:.2f} P={v['precision']:.2f} R={v['recall']:.2f} n={int(v['support'])}", file=sys.stderr)
    print(f"  ... ({len(class_items) - 10} more classes above)", file=sys.stderr)


if __name__ == "__main__":
    main()
