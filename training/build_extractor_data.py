#!/usr/bin/env python3
"""Build extraction training data using fleet LLMs as teachers.

Takes classified logs and generates OCSF JSON labels using teacher models.
Output is chat-format JSONL suitable for QLoRA fine-tuning.

Usage:
    python scripts/build_extractor_data.py \
        --input /tmp/extraction_candidates.jsonl \
        --output data/extractor_training.jsonl \
        --schemas-dir schemas/ocsf_v1.3/classes \
        --concurrency 6
"""

import argparse
import asyncio
import json
import re
import sys
import time
from pathlib import Path

import aiohttp

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

ENDPOINTS = [
    {"url": "http://localhost:8000/v1/chat/completions", "model": "model-a", "name": "model-a"},
    {"url": "http://localhost:8001/v1/chat/completions", "model": "model-b", "name": "model-b"},
    {"url": "http://localhost:8002/v1/chat/completions", "model": "model-c", "name": "model-c"},
]


def build_schema_context(schema: dict) -> str:
    attrs = schema.get("attributes", {})
    lines = [
        f"Class: {schema['class_name']} (UID: {schema['class_uid']})",
        f"Category UID: {schema.get('category_uid', schema['class_uid'] // 1000)}",
    ]
    desc = schema.get("description", "")
    if desc:
        lines.append(f"Description: {desc[:200]}")
    lines.append("")
    lines.append("Fields:")
    for name, spec in attrs.items():
        req = "**REQUIRED**" if spec.get("requirement") == "required" else spec.get("requirement", "optional")
        ftype = spec.get("type", "string")
        fdesc = spec.get("description", "")[:60]
        lines.append(f"  - {name} ({ftype}, {req}): {fdesc}")
    return "\n".join(lines)


def extract_json(text: str) -> dict | None:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"```(?:json)?\s*\n?", "", text).strip().rstrip("`")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    brace = text.find("{")
    if brace >= 0:
        depth = 0
        for i in range(brace, len(text)):
            if text[i] == "{": depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[brace:i+1])
                    except json.JSONDecodeError:
                        break
    return None


async def extract_one(
    sem: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    record: dict,
    schemas: dict,
    endpoint: dict,
    output_file,
    stats: dict,
):
    async with sem:
        uid = record["class_uid"]
        schema = schemas.get(uid)
        if not schema:
            stats["no_schema"] += 1
            return

        schema_ctx = build_schema_context(schema)
        user_prompt = f"Schema:\n{schema_ctx}\n\nRaw log:\n{record['raw_log']}\n\nExtract OCSF JSON:"

        payload = {
            "model": endpoint["model"],
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 2048,
            "chat_template_kwargs": {"enable_thinking": False},
        }

        try:
            async with session.post(
                endpoint["url"], json=payload,
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=90),
            ) as resp:
                if resp.status != 200:
                    stats["api_error"] += 1
                    return
                result = await resp.json()
                content = result["choices"][0]["message"]["content"]
        except Exception as e:
            stats["api_error"] += 1
            return

        extracted = extract_json(content)
        if extracted is None:
            stats["parse_error"] += 1
            return

        # Validate basic structure
        if not isinstance(extracted, dict):
            stats["parse_error"] += 1
            return
        if "class_uid" not in extracted:
            extracted["class_uid"] = uid
        if extracted.get("class_uid") != uid:
            extracted["class_uid"] = uid  # Force correct class

        # Build chat-format training record
        # The assistant output is compact JSON (no whitespace)
        training_record = {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
                {"role": "assistant", "content": json.dumps(extracted, separators=(",", ":"))},
            ],
            "class_uid": uid,
            "class_name": record.get("class_name", ""),
            "field_count": len(extracted),
            "teacher": endpoint["name"],
        }

        output_file.write(json.dumps(training_record) + "\n")
        output_file.flush()
        stats["success"] += 1

        total = stats["success"] + stats["api_error"] + stats["parse_error"] + stats["no_schema"]
        if total % 100 == 0:
            elapsed = time.time() - stats["start"]
            rate = stats["success"] / elapsed if elapsed > 0 else 0
            print(f"  {total}/{stats['total']}: {stats['success']} ok, "
                  f"{stats['api_error']} api_err, {stats['parse_error']} parse_err, "
                  f"{rate:.1f}/sec", file=sys.stderr)


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--schemas-dir", required=True)
    parser.add_argument("--concurrency", type=int, default=6)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    # Load schemas
    schemas = {}
    for f in Path(args.schemas_dir).glob("class_*.json"):
        with open(f) as fh:
            s = json.load(fh)
        schemas[s["class_uid"]] = s
    print(f"Loaded {len(schemas)} schemas", file=sys.stderr)

    # Load candidates
    records = [json.loads(l) for l in open(args.input)]

    # Resume support
    done = set()
    if args.resume and Path(args.output).exists():
        with open(args.output) as f:
            for line in f:
                try:
                    d = json.loads(line)
                    user_msg = d["messages"][1]["content"]
                    if "Raw log:\n" in user_msg:
                        raw = user_msg.split("Raw log:\n")[1].split("\n\nExtract")[0][:100]
                        done.add(raw)
                except Exception:
                    pass
        print(f"Resuming: {len(done)} already done", file=sys.stderr)
        records = [r for r in records if r["raw_log"][:100] not in done]

    print(f"Processing {len(records)} records with concurrency={args.concurrency}", file=sys.stderr)

    stats = {
        "success": 0, "api_error": 0, "parse_error": 0, "no_schema": 0,
        "total": len(records), "start": time.time(),
    }

    sem = asyncio.Semaphore(args.concurrency)
    mode = "a" if args.resume else "w"

    async with aiohttp.ClientSession() as session:
        with open(args.output, mode) as out:
            # Round-robin across endpoints
            tasks = []
            for i, record in enumerate(records):
                endpoint = ENDPOINTS[i % len(ENDPOINTS)]
                tasks.append(extract_one(sem, session, record, schemas, endpoint, out, stats))
            await asyncio.gather(*tasks)

    elapsed = time.time() - stats["start"]
    print(f"\nComplete in {elapsed:.0f}s:", file=sys.stderr)
    print(f"  Success: {stats['success']}/{stats['total']}", file=sys.stderr)
    print(f"  API errors: {stats['api_error']}", file=sys.stderr)
    print(f"  Parse errors: {stats['parse_error']}", file=sys.stderr)
    print(f"  Rate: {stats['success']/max(elapsed,1):.1f}/sec", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
