#!/usr/bin/env python3
"""Fine-tune Llama 3.2 3B as OCSF extractor using Unsloth QLoRA.

Trains on chat-format extraction examples (system + schema prompt → OCSF JSON).
Produces a LoRA adapter that can be merged and quantized to GGUF for CPU.

Usage (inside Unsloth container):
    python3 train_extractor.py \
        --input data/extractor_training.jsonl \
        --output models/shrike-extractor \
        --epochs 3 \
        --lr 2e-4
"""

import argparse
import json
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Train OCSF extractor with Unsloth")
    parser.add_argument("--input", required=True, help="Chat-format training JSONL")
    parser.add_argument("--output", required=True, help="Output directory for model")
    parser.add_argument("--base-model", default="unsloth/Llama-3.2-3B-Instruct", help="Base model")
    parser.add_argument("--epochs", type=int, default=3, help="Training epochs")
    parser.add_argument("--lr", type=float, default=2e-4, help="Learning rate")
    parser.add_argument("--batch-size", type=int, default=4, help="Batch size")
    parser.add_argument("--grad-accum", type=int, default=4, help="Gradient accumulation steps")
    parser.add_argument("--max-length", type=int, default=2048, help="Max sequence length")
    parser.add_argument("--lora-r", type=int, default=32, help="LoRA rank")
    parser.add_argument("--val-split", type=float, default=0.1, help="Validation split")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--quantize", action="store_true", help="Also export GGUF Q4_K_M")
    args = parser.parse_args()

    from unsloth import FastLanguageModel
    from unsloth.chat_templates import get_chat_template
    from trl import SFTTrainer
    from transformers import TrainingArguments
    from datasets import Dataset
    import torch

    # Load training data
    print(f"Loading training data from {args.input}...", file=sys.stderr)
    records = [json.loads(l) for l in open(args.input)]

    # Split
    import random
    random.seed(args.seed)
    random.shuffle(records)
    split = int(len(records) * (1 - args.val_split))
    train_records = records[:split]
    val_records = records[split:]
    print(f"  Train: {len(train_records)}, Val: {len(val_records)}", file=sys.stderr)

    # Load model with QLoRA
    print(f"Loading {args.base_model} with QLoRA (r={args.lora_r})...", file=sys.stderr)
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.base_model,
        max_seq_length=args.max_length,
        dtype=None,  # Auto-detect
        load_in_4bit=True,
    )

    model = FastLanguageModel.get_peft_model(
        model,
        r=args.lora_r,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                         "gate_proj", "up_proj", "down_proj"],
        lora_alpha=args.lora_r,  # alpha = rank for stable training
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=args.seed,
    )

    # Apply chat template
    tokenizer = get_chat_template(tokenizer, chat_template="llama-3.1")

    # Format data for SFT
    def format_example(record):
        messages = record["messages"]
        return {"text": tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)}

    train_dataset = Dataset.from_list([format_example(r) for r in train_records])
    val_dataset = Dataset.from_list([format_example(r) for r in val_records])

    print(f"  Train examples: {len(train_dataset)}", file=sys.stderr)
    print(f"  Val examples: {len(val_dataset)}", file=sys.stderr)

    # Sample token lengths
    sample_lengths = []
    for ex in train_dataset.select(range(min(50, len(train_dataset)))):
        toks = tokenizer(ex["text"], truncation=False)
        sample_lengths.append(len(toks["input_ids"]))
    avg_len = sum(sample_lengths) / len(sample_lengths)
    max_len = max(sample_lengths)
    print(f"  Token lengths: avg={avg_len:.0f}, max={max_len}, target={args.max_length}", file=sys.stderr)

    # Training
    output_dir = Path(args.output)
    training_args = TrainingArguments(
        output_dir=str(output_dir / "checkpoints"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        weight_decay=0.01,
        warmup_ratio=0.05,
        lr_scheduler_type="cosine",
        eval_strategy="epoch",
        save_strategy="no",
        logging_steps=25,
        seed=args.seed,
        bf16=True,
        optim="adamw_8bit",
        report_to="none",
        max_grad_norm=1.0,
    )

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        args=training_args,
        max_seq_length=args.max_length,
        dataset_text_field="text",
        packing=True,
    )

    print("Starting training...", file=sys.stderr)
    result = trainer.train()
    print(f"Training complete: loss={result.metrics['train_loss']:.4f}", file=sys.stderr)

    eval_result = trainer.evaluate()
    print(f"Eval loss: {eval_result['eval_loss']:.4f}", file=sys.stderr)

    # Save
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save LoRA adapter (small, always fits) — save to /workspace which is the mounted volume
    lora_path = output_dir / "lora"
    print(f"Saving LoRA adapter to {lora_path}...", file=sys.stderr)
    lora_path.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(lora_path))
    tokenizer.save_pretrained(str(lora_path))

    # Save training metrics
    json.dump({
        "train": result.metrics,
        "eval": eval_result,
        "base_model": args.base_model,
        "lora_r": args.lora_r,
        "epochs": args.epochs,
        "lr": args.lr,
        "num_train": len(train_records),
        "num_val": len(val_records),
        "avg_token_length": avg_len,
    }, open(output_dir / "training_metrics.json", "w"), indent=2)

    # Quantize to GGUF if requested (needs disk space)
    if args.quantize:
        try:
            print("Quantizing to GGUF Q4_K_M...", file=sys.stderr)
            model.save_pretrained_gguf(
                str(output_dir / "gguf"),
                tokenizer,
                quantization_method="q4_k_m",
            )
            print(f"GGUF saved to {output_dir / 'gguf'}", file=sys.stderr)
        except Exception as e:
            print(f"GGUF export failed (disk space?): {e}", file=sys.stderr)
            print("LoRA adapter saved — merge and quantize manually.", file=sys.stderr)

    print(f"\nModel saved to: {output_dir}", file=sys.stderr)


if __name__ == "__main__":
    main()
