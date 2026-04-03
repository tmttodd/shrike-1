#!/usr/bin/env python3
"""Build training data for the schema-injected extractor model.

Takes classified ground truth logs and uses a teacher model to generate
OCSF JSON for each, with the correct schema injected. Output is in
chat format suitable for QLoRA fine-tuning.

Usage:
    python scripts/build_extractor_training.py \
        --ground-truth data/ground_truth/classification_ground_truth.jsonl \
        --schemas-dir schemas/ocsf_v1.3/classes \
        --output data/extractor_training.jsonl \
        --teacher-api http://localhost:11434/v1 \
        --teacher-model llama3.2:3b \
        --concurrency 4
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path


SYSTEM_PROMPT = """You are a log normalization engine. Given a raw log line and an OCSF event class schema, extract the relevant fields into a valid JSON object.

Rules:
1. Output ONLY valid JSON — no explanation, no markdown, no comments.
2. Include class_uid, class_name, category_uid, category_name, activity_id, severity_id, and time.
3. Extract values directly from the log. Do not invent or hallucinate values.
4. Use the exact field names from the schema.
5. If a field's value cannot be determined from the log, omit it entirely.
6. For severity_id: 0=Unknown, 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical, 6=Fatal.
7. For activity_id: 0=Unknown, 1=Logon/Create/Allow, 2=Logoff/Read/Deny, 99=Other.
8. Preserve original values (IPs, usernames, timestamps) exactly as they appear."""


def build_schema_context(schema: dict) -> str:
    """Build compact schema description for prompt injection."""
    attrs = schema.get("attributes", {})
    if not attrs:
        return f"Class: {schema['class_name']} (UID: {schema['class_uid']})\nNo class-specific fields defined."

    lines = [
        f"Class: {schema['class_name']} (UID: {schema['class_uid']})",
        f"Category: {schema.get('category_uid', 'unknown')}",
        f"Description: {schema.get('description', '')[:200]}",
        "",
        "Fields:",
    ]

    for name, spec in attrs.items():
        req = spec.get("requirement", "optional")
        ftype = spec.get("type", "string")
        desc = spec.get("description", "")[:80]
        marker = "**REQUIRED**" if req == "required" else req
        lines.append(f"  - {name} ({ftype}, {marker}): {desc}")

    return "\n".join(lines)


async def call_teacher(
    session,
    api_base: str,
    model: str,
    api_key: str,
    system_prompt: str,
    user_prompt: str,
    temperature: float = 0.1,
    max_tokens: int = 2048,
) -> str | None:
    """Call the teacher model API."""
    import aiohttp

    url = f"{api_base}/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    try:
        async with session.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=aiohttp.ClientTimeout(total=120),
        ) as resp:
            if resp.status != 200:
                return None
            result = await resp.json()
            return result["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"  API error: {e}", file=sys.stderr)
        return None


def extract_json(text: str) -> dict | None:
    """Extract JSON from LLM output."""
    import re

    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass

    brace_start = text.find("{")
    if brace_start >= 0:
        depth = 0
        for i in range(brace_start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[brace_start : i + 1])
                    except json.JSONDecodeError:
                        break
    return None


async def process_record(
    sem: asyncio.Semaphore,
    session,
    record: dict,
    schemas: dict[int, dict],
    api_base: str,
    model: str,
    api_key: str,
    output_file,
    stats: dict,
):
    """Process a single ground truth record."""
    async with sem:
        raw_log = record["raw_log"]
        class_uid = record["class_uid"]
        class_name = record.get("class_name", "Unknown")

        schema = schemas.get(class_uid)
        if schema is None:
            stats["no_schema"] += 1
            return

        schema_context = build_schema_context(schema)
        user_prompt = f"Schema:\n{schema_context}\n\nRaw log:\n{raw_log}\n\nExtract OCSF JSON:"

        response = await call_teacher(
            session, api_base, model, api_key, SYSTEM_PROMPT, user_prompt
        )

        if response is None:
            stats["api_error"] += 1
            return

        extracted = extract_json(response)
        if extracted is None:
            stats["parse_error"] += 1
            return

        # Build chat-format training record
        training_record = {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
                {"role": "assistant", "content": json.dumps(extracted, separators=(",", ":"))},
            ],
            "class_uid": class_uid,
            "class_name": class_name,
        }

        output_file.write(json.dumps(training_record) + "\n")
        output_file.flush()
        stats["success"] += 1

        total = stats["success"] + stats["api_error"] + stats["parse_error"] + stats["no_schema"]
        if total % 50 == 0:
            elapsed = time.time() - stats["start_time"]
            rate = stats["success"] / elapsed if elapsed > 0 else 0
            print(
                f"  Progress: {total}/{stats['total']} | "
                f"Success: {stats['success']} | Errors: {stats['api_error']+stats['parse_error']} | "
                f"Rate: {rate:.1f}/sec",
                file=sys.stderr,
            )


async def main():
    import aiohttp

    parser = argparse.ArgumentParser(description="Build extractor training data")
    parser.add_argument("--ground-truth", required=True, help="Ground truth JSONL file")
    parser.add_argument("--schemas-dir", required=True, help="Per-class schema directory")
    parser.add_argument("--output", required=True, help="Output training JSONL file")
    parser.add_argument("--teacher-api", default="http://localhost:11434/v1", help="Teacher API base URL")
    parser.add_argument("--teacher-model", default="llama3.2:3b", help="Teacher model name")
    parser.add_argument("--api-key", default="not-needed", help="API key")
    parser.add_argument("--concurrency", type=int, default=4, help="Max concurrent requests")
    parser.add_argument("--max-records", type=int, default=0, help="Max records to process (0=all)")
    parser.add_argument("--resume", action="store_true", help="Resume from existing output")
    args = parser.parse_args()

    # Load schemas
    schemas_dir = Path(args.schemas_dir)
    schemas: dict[int, dict] = {}
    for f in schemas_dir.glob("class_*.json"):
        with open(f) as fh:
            schema = json.load(fh)
        schemas[schema["class_uid"]] = schema
    print(f"Loaded {len(schemas)} schemas", file=sys.stderr)

    # Load ground truth
    records = []
    with open(args.ground_truth) as f:
        for line in f:
            records.append(json.loads(line))

    if args.max_records > 0:
        records = records[:args.max_records]

    # Check for resume
    done_logs = set()
    if args.resume and Path(args.output).exists():
        with open(args.output) as f:
            for line in f:
                try:
                    d = json.loads(line)
                    user_msg = d["messages"][1]["content"]
                    # Extract raw log from user message
                    if "Raw log:\n" in user_msg:
                        raw = user_msg.split("Raw log:\n")[1].split("\n\nExtract")[0]
                        done_logs.add(raw[:200])
                except Exception:
                    pass
        print(f"Resuming: {len(done_logs)} already processed", file=sys.stderr)
        records = [r for r in records if r["raw_log"][:200] not in done_logs]

    print(f"Processing {len(records)} records with concurrency={args.concurrency}", file=sys.stderr)

    stats = {
        "success": 0,
        "api_error": 0,
        "parse_error": 0,
        "no_schema": 0,
        "total": len(records),
        "start_time": time.time(),
    }

    sem = asyncio.Semaphore(args.concurrency)
    mode = "a" if args.resume else "w"

    async with aiohttp.ClientSession() as session:
        with open(args.output, mode) as out:
            tasks = [
                process_record(sem, session, record, schemas, args.teacher_api, args.teacher_model, args.api_key, out, stats)
                for record in records
            ]
            await asyncio.gather(*tasks)

    elapsed = time.time() - stats["start_time"]
    print(f"\nComplete in {elapsed:.0f}s:", file=sys.stderr)
    print(f"  Success: {stats['success']}", file=sys.stderr)
    print(f"  API errors: {stats['api_error']}", file=sys.stderr)
    print(f"  Parse errors: {stats['parse_error']}", file=sys.stderr)
    print(f"  No schema: {stats['no_schema']}", file=sys.stderr)
    print(f"  Rate: {stats['success']/max(elapsed,1):.1f} records/sec", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
