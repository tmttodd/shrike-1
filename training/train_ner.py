#!/usr/bin/env python3
"""Fine-tune SecureBERT 2.0 for log entity NER (Named Entity Recognition).

Loads whitespace-tokenized training data with BIO tags, aligns them to
SecureBERT's subword tokenizer, and fine-tunes for token classification.

Entity types (15): IP, PORT, USER, HOSTNAME, PROCESS, PID, PATH, TIMESTAMP,
                   PROTOCOL, ACTION, STATUS, FINDING, SID, MAC, EMAIL

Label scheme: BIO (B-X / I-X / O) = 31 labels total.

Usage:
    python3 training/train_ner.py             # Full training (5 epochs)
    python3 training/train_ner.py --dry-run   # Quick test (10 steps)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import warnings
from pathlib import Path

import numpy as np

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("train_ner")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TRAINING_DATA = PROJECT_ROOT / "training" / "ner_training_hf.jsonl"
STATS_FILE = PROJECT_ROOT / "training" / "ner_training_stats.json"
OUTPUT_DIR = PROJECT_ROOT / "models" / "shrike-ner"

MODEL_NAME = "cisco-ai/SecureBERT2.0-base"
MAX_SEQ_LENGTH = 512  # ModernBERT supports up to 8192 but 512 is efficient

# ---------------------------------------------------------------------------
# Label definitions (must match build_ner_training.py)
# ---------------------------------------------------------------------------

NER_LABELS = [
    "O",
    "B-IP", "I-IP",
    "B-PORT", "I-PORT",
    "B-USER", "I-USER",
    "B-HOSTNAME", "I-HOSTNAME",
    "B-PROCESS", "I-PROCESS",
    "B-PID", "I-PID",
    "B-PATH", "I-PATH",
    "B-TIMESTAMP", "I-TIMESTAMP",
    "B-PROTOCOL", "I-PROTOCOL",
    "B-ACTION", "I-ACTION",
    "B-STATUS", "I-STATUS",
    "B-FINDING", "I-FINDING",
    "B-SID", "I-SID",
    "B-MAC", "I-MAC",
    "B-EMAIL", "I-EMAIL",
]

LABEL_TO_ID = {label: i for i, label in enumerate(NER_LABELS)}
ID_TO_LABEL = {i: label for i, label in enumerate(NER_LABELS)}
NUM_LABELS = len(NER_LABELS)

# The ignore index for cross-entropy loss (subword tokens that don't get labels)
IGNORE_INDEX = -100


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_training_data(path: Path) -> list[dict]:
    """Load JSONL training data. Each line has tokens, ner_tags (int), ner_tag_names."""
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            records.append(rec)
    log.info(f"Loaded {len(records)} training examples from {path}")
    return records


def compute_class_weights(records: list[dict]) -> np.ndarray:
    """Compute inverse-frequency class weights to handle label imbalance.

    The O tag dominates (~82% of tokens). We compute weights inversely
    proportional to frequency so minority entity classes get higher loss.
    """
    counts = np.zeros(NUM_LABELS, dtype=np.float64)
    for rec in records:
        for tag_id in rec["ner_tags"]:
            if 0 <= tag_id < NUM_LABELS:
                counts[tag_id] += 1

    # Avoid division by zero for unseen labels
    counts = np.maximum(counts, 1.0)
    total = counts.sum()
    # Inverse frequency, normalized so mean weight = 1.0
    weights = total / (NUM_LABELS * counts)
    # Cap maximum weight to avoid instability on very rare labels
    weights = np.minimum(weights, 20.0)

    log.info("Class weights (top-5 highest):")
    sorted_idx = np.argsort(weights)[::-1]
    for i in sorted_idx[:5]:
        log.info(f"  {NER_LABELS[i]:15s}: {weights[i]:.2f} (count={int(counts[i])})")

    return weights.astype(np.float32)


# ---------------------------------------------------------------------------
# Tokenization and label alignment
# ---------------------------------------------------------------------------

def tokenize_and_align_labels(
    examples: dict,
    tokenizer,
    max_length: int = MAX_SEQ_LENGTH,
) -> dict:
    """Tokenize whitespace tokens with the subword tokenizer and align BIO labels.

    For each whitespace token that gets split into multiple subwords:
    - The first subword gets the original BIO label
    - Subsequent subwords get IGNORE_INDEX (ignored by loss function)

    This is the standard approach for NER with subword tokenizers.
    """
    tokenized = tokenizer(
        examples["tokens"],
        truncation=True,
        max_length=max_length,
        padding=False,  # We'll pad in the data collator
        is_split_into_words=True,  # Input is already whitespace-tokenized
    )

    all_labels = []
    for i, label_ids in enumerate(examples["ner_tags"]):
        word_ids = tokenized.word_ids(batch_index=i)
        previous_word_idx = None
        aligned_labels = []
        for word_idx in word_ids:
            if word_idx is None:
                # Special tokens ([CLS], [SEP], padding)
                aligned_labels.append(IGNORE_INDEX)
            elif word_idx != previous_word_idx:
                # First subword of a new word: use original label
                if word_idx < len(label_ids):
                    aligned_labels.append(label_ids[word_idx])
                else:
                    aligned_labels.append(IGNORE_INDEX)
            else:
                # Subsequent subword of the same word: ignore in loss
                aligned_labels.append(IGNORE_INDEX)
            previous_word_idx = word_idx
        all_labels.append(aligned_labels)

    tokenized["labels"] = all_labels
    return tokenized


# ---------------------------------------------------------------------------
# Metrics (seqeval-based)
# ---------------------------------------------------------------------------

def build_compute_metrics(id_to_label: dict):
    """Build a compute_metrics function for HuggingFace Trainer.

    Uses seqeval for proper entity-level precision/recall/F1.
    """
    from seqeval.metrics import (
        classification_report,
        f1_score,
        precision_score,
        recall_score,
    )

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        predictions = np.argmax(logits, axis=-1)

        # Convert integer predictions/labels back to string tags,
        # filtering out IGNORE_INDEX positions
        true_labels = []
        pred_labels = []

        for pred_seq, label_seq in zip(predictions, labels):
            true_seq = []
            pred_seq_str = []
            for p, l in zip(pred_seq, label_seq):
                if l == IGNORE_INDEX:
                    continue
                true_seq.append(id_to_label.get(l, "O"))
                pred_seq_str.append(id_to_label.get(p, "O"))
            true_labels.append(true_seq)
            pred_labels.append(pred_seq_str)

        # Entity-level metrics
        f1 = f1_score(true_labels, pred_labels, average="weighted")
        precision = precision_score(true_labels, pred_labels, average="weighted")
        recall = recall_score(true_labels, pred_labels, average="weighted")

        # Print detailed per-entity report at each eval
        report = classification_report(true_labels, pred_labels, digits=4)
        log.info(f"\n{report}")

        return {
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }

    return compute_metrics


# ---------------------------------------------------------------------------
# Custom Trainer with class-weighted loss
# ---------------------------------------------------------------------------

def build_weighted_trainer_class(class_weights_tensor):
    """Build a Trainer subclass that uses class-weighted cross-entropy loss."""
    import torch
    from transformers import Trainer

    class WeightedNERTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
            labels = inputs.pop("labels")
            outputs = model(**inputs)
            logits = outputs.logits

            # Reshape for cross-entropy: (batch * seq_len, num_labels)
            loss_fct = torch.nn.CrossEntropyLoss(
                weight=class_weights_tensor.to(logits.device),
                ignore_index=IGNORE_INDEX,
            )
            loss = loss_fct(
                logits.view(-1, NUM_LABELS),
                labels.view(-1),
            )

            return (loss, outputs) if return_outputs else loss

    return WeightedNERTrainer


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Fine-tune SecureBERT 2.0 for NER")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Quick test: load data and model, train for 10 steps only",
    )
    parser.add_argument(
        "--epochs", type=int, default=5,
        help="Number of training epochs (default: 5)",
    )
    parser.add_argument(
        "--batch-size", type=int, default=16,
        help="Training batch size (default: 16)",
    )
    parser.add_argument(
        "--learning-rate", type=float, default=5e-5,
        help="Learning rate (default: 5e-5)",
    )
    parser.add_argument(
        "--output-dir", type=str, default=str(OUTPUT_DIR),
        help=f"Output directory for model (default: {OUTPUT_DIR})",
    )
    args = parser.parse_args()

    # -----------------------------------------------------------------------
    # Check GPU availability
    # -----------------------------------------------------------------------
    import torch

    if torch.cuda.is_available():
        device_name = torch.cuda.get_device_name(0)
        log.info(f"GPU available: {device_name}")
        log.info(f"CUDA version: {torch.version.cuda}")
    elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        log.info("Apple MPS (Metal) backend available — using GPU acceleration")
    else:
        log.warning("No GPU detected! Training will be SLOW on CPU.")
        log.warning("For real training, use a machine with a CUDA GPU.")

    # -----------------------------------------------------------------------
    # Load data
    # -----------------------------------------------------------------------
    if not TRAINING_DATA.exists():
        log.error(f"Training data not found: {TRAINING_DATA}")
        log.error("Run `python3 training/build_ner_training.py` first.")
        sys.exit(1)

    records = load_training_data(TRAINING_DATA)

    # Compute class weights before converting to HF Dataset
    class_weights = compute_class_weights(records)

    # -----------------------------------------------------------------------
    # Build HuggingFace Dataset
    # -----------------------------------------------------------------------
    from datasets import Dataset

    # Convert list of dicts to dict of lists
    data_dict = {
        "tokens": [r["tokens"] for r in records],
        "ner_tags": [r["ner_tags"] for r in records],
    }
    dataset = Dataset.from_dict(data_dict)

    # Train/val split (80/20, stratified shuffle)
    split = dataset.train_test_split(test_size=0.2, seed=42)
    train_dataset = split["train"]
    val_dataset = split["test"]

    log.info(f"Train: {len(train_dataset)} examples, Val: {len(val_dataset)} examples")

    # -----------------------------------------------------------------------
    # Load tokenizer and model
    # -----------------------------------------------------------------------
    from transformers import AutoModelForTokenClassification, AutoTokenizer

    log.info(f"Loading tokenizer: {MODEL_NAME}")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    log.info(f"Loading model: {MODEL_NAME} ({NUM_LABELS} labels)")
    model = AutoModelForTokenClassification.from_pretrained(
        MODEL_NAME,
        num_labels=NUM_LABELS,
        id2label=ID_TO_LABEL,
        label2id=LABEL_TO_ID,
    )

    # Log model size
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    log.info(f"Model parameters: {total_params:,} total, {trainable_params:,} trainable")

    # -----------------------------------------------------------------------
    # Tokenize and align labels
    # -----------------------------------------------------------------------
    log.info("Tokenizing and aligning labels...")

    tokenize_fn = lambda examples: tokenize_and_align_labels(examples, tokenizer)

    train_tokenized = train_dataset.map(
        tokenize_fn,
        batched=True,
        remove_columns=train_dataset.column_names,
        desc="Tokenizing train",
    )
    val_tokenized = val_dataset.map(
        tokenize_fn,
        batched=True,
        remove_columns=val_dataset.column_names,
        desc="Tokenizing val",
    )

    # -----------------------------------------------------------------------
    # Training arguments
    # -----------------------------------------------------------------------
    from transformers import DataCollatorForTokenClassification, TrainingArguments

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.dry_run:
        training_args = TrainingArguments(
            output_dir=str(output_dir / "checkpoints"),
            max_steps=10,
            per_device_train_batch_size=4,
            per_device_eval_batch_size=4,
            eval_strategy="steps",
            eval_steps=10,
            logging_steps=1,
            save_strategy="no",
            learning_rate=args.learning_rate,
            weight_decay=0.01,
            warmup_steps=2,
            report_to="none",
            fp16=torch.cuda.is_available(),
            dataloader_num_workers=0,
        )
    else:
        training_args = TrainingArguments(
            output_dir=str(output_dir / "checkpoints"),
            num_train_epochs=args.epochs,
            per_device_train_batch_size=args.batch_size,
            per_device_eval_batch_size=args.batch_size * 2,
            eval_strategy="epoch",
            save_strategy="epoch",
            logging_steps=50,
            learning_rate=args.learning_rate,
            weight_decay=0.01,
            warmup_steps=500,
            load_best_model_at_end=True,
            metric_for_best_model="f1",
            greater_is_better=True,
            save_total_limit=2,
            report_to="none",
            fp16=torch.cuda.is_available(),
            dataloader_num_workers=2,
        )

    # Data collator handles dynamic padding
    data_collator = DataCollatorForTokenClassification(
        tokenizer=tokenizer,
        label_pad_token_id=IGNORE_INDEX,
    )

    # -----------------------------------------------------------------------
    # Build trainer with class-weighted loss
    # -----------------------------------------------------------------------
    class_weights_tensor = torch.tensor(class_weights)
    WeightedTrainer = build_weighted_trainer_class(class_weights_tensor)

    compute_metrics = build_compute_metrics(ID_TO_LABEL)

    trainer = WeightedTrainer(
        model=model,
        args=training_args,
        train_dataset=train_tokenized,
        eval_dataset=val_tokenized,
        data_collator=data_collator,
        processing_class=tokenizer,
        compute_metrics=compute_metrics,
    )

    # -----------------------------------------------------------------------
    # Train
    # -----------------------------------------------------------------------
    mode = "DRY RUN (10 steps)" if args.dry_run else f"FULL ({args.epochs} epochs)"
    log.info(f"Starting training: {mode}")
    log.info(f"  Batch size: {training_args.per_device_train_batch_size}")
    log.info(f"  Learning rate: {training_args.learning_rate}")
    log.info(f"  Weight decay: {training_args.weight_decay}")
    log.info(f"  Warmup steps: {training_args.warmup_steps}")

    train_result = trainer.train()

    # Log training metrics
    log.info(f"Training complete!")
    log.info(f"  Train loss: {train_result.training_loss:.4f}")
    log.info(f"  Train runtime: {train_result.metrics.get('train_runtime', 0):.1f}s")
    log.info(f"  Train samples/sec: {train_result.metrics.get('train_samples_per_second', 0):.1f}")

    # -----------------------------------------------------------------------
    # Evaluate
    # -----------------------------------------------------------------------
    log.info("Running final evaluation...")
    eval_results = trainer.evaluate()
    log.info(f"Eval results:")
    for key, value in sorted(eval_results.items()):
        if isinstance(value, float):
            log.info(f"  {key}: {value:.4f}")
        else:
            log.info(f"  {key}: {value}")

    # -----------------------------------------------------------------------
    # Save model
    # -----------------------------------------------------------------------
    if not args.dry_run:
        save_path = output_dir
        log.info(f"Saving model to {save_path}")
        trainer.save_model(str(save_path))
        tokenizer.save_pretrained(str(save_path))

        # Save label mapping alongside the model
        label_map_path = save_path / "label_map.json"
        with open(label_map_path, "w") as f:
            json.dump({
                "id2label": ID_TO_LABEL,
                "label2id": LABEL_TO_ID,
                "labels": NER_LABELS,
            }, f, indent=2)
        log.info(f"Label map saved to {label_map_path}")
    else:
        log.info("Dry run complete - model NOT saved (use without --dry-run for full training)")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print(f"\n{'='*60}")
    print(f"Shrike NER Training {'(DRY RUN) ' if args.dry_run else ''}Complete")
    print(f"{'='*60}")
    print(f"Model:          {MODEL_NAME}")
    print(f"Labels:         {NUM_LABELS} ({(NUM_LABELS-1)//2} entity types + O)")
    print(f"Train examples: {len(train_tokenized)}")
    print(f"Val examples:   {len(val_tokenized)}")
    print(f"Train loss:     {train_result.training_loss:.4f}")
    if "eval_f1" in eval_results:
        print(f"Val F1:         {eval_results['eval_f1']:.4f}")
        print(f"Val Precision:  {eval_results['eval_precision']:.4f}")
        print(f"Val Recall:     {eval_results['eval_recall']:.4f}")
    if not args.dry_run:
        print(f"Model saved to: {output_dir}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
