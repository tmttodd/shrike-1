# Shrike — Log Normalization Engine

> **Purpose**: Any log format in, OCSF out. No parsers to write.
> **Repo**: https://github.com/tmttodd/shrike
> **Status**: Design phase

## Architecture

Multi-stage pipeline, each stage independently testable and upgradeable:

1. **Detector** — regex/heuristic format fingerprinting (<1ms)
2. **Classifier** — embedding similarity against 65 OCSF class vectors (~5ms)
3. **Filter** — YAML-configurable filter packs (<1ms)
4. **Extractor** — fine-tuned 3B LLM with class-specific schema injection (~500ms CPU)
5. **Validator** — JSON schema compliance check, auto-retry (<1ms)

## Key Files

| Path | Purpose |
|------|---------|
| `shrike/pipeline.py` | Main pipeline orchestration |
| `shrike/detector/` | Log format detection |
| `shrike/classifier/` | OCSF class classification via embeddings |
| `shrike/extractor/` | LLM-based field extraction with schema injection |
| `shrike/filter/` | Filter pack engine |
| `shrike/validator/` | OCSF schema validation |
| `models/` | Model artifacts (gitignored) |
| `schemas/ocsf_v1.3/` | OCSF class schemas |
| `filters/` | Filter pack YAML files |
| `tests/` | Unit, integration, and benchmark tests |
| `scripts/` | Training, data generation, benchmarking scripts |

## Design Principles

- CPU-first, GPU-optional
- OCSF v1.3 native output
- No source-specific configuration
- Stateless, horizontally scalable
- ~2.5GB container image
- Filter packs for noise reduction

## Development

```bash
# Install
pip install -e ".[dev]"

# Test
pytest tests/

# Run locally
python -m shrike.pipeline --input sample.log

# Docker
docker build -t shrike .
docker run -p 8080:8080 shrike
```

## Prior Art

This project builds on research from Project 027 (OCSF Log Model) in the ai workspace:
- Training data pipeline (Splunkbase, public datasets, teacher labeling)
- Benchmark framework (golden test set, OCSF scorer)
- Model training scripts (Unsloth/QLoRA)

Key learning: single-model approach (classify + extract in one call) tops out at ~60% class accuracy on 8B. Two-stage approach (embed classify + schema-injected extract) is the correct architecture.
