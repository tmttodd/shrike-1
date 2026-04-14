# ML Dependencies in Shrike

Shrike has optional ML dependencies for enhanced classification and extraction capabilities.

## What's Required vs Optional

| Component | Required | Purpose | Fallback |
|-----------|----------|---------|----------|
| **Pattern Engine** | ✅ Yes | 2,052 YAML patterns, 14 format detectors | N/A |
| **Classifier** (DistilBERT) | ❌ Optional | 45-class OCSF classification | Falls back to pattern-only mode |
| **NER Model** (SecureBERT) | ❌ Optional | Named entity extraction | Falls back to pattern extraction |
| **LLM Extractor** | ❌ Optional | Tier 2-3 extraction for complex logs | Falls back to Tier 1 patterns |

## Installation

### Pattern-Only Mode (Default)
Shrike works out of the box with **no ML dependencies**:
```bash
pip install -e ".[dev]"
# or
pip install -e "."
```

This provides:
- 14 format detectors (syslog, JSON, CEF, LEEF, etc.)
- 2,052 YAML extraction patterns
- 6-tier extraction engine (Tiers 0-1.5 are local)
- OCSF schema validation
- Destination routing

### Full ML Mode
For enhanced classification and extraction:
```bash
pip install -e ".[ml]"
```

This installs:
- `torch` - PyTorch for model inference
- `transformers` - Hugging Face models
- Pre-trained DistilBERT classifier (~85MB)
- Pre-trained NER model (~120MB)

### LLM Extraction (Optional)
For Tier 2-3 extraction of complex/unseen formats:
```bash
# Configure via environment variables
export SHRIKE_LLM_URL=http://localhost:11434/v1  # Ollama, vLLM, etc.
export SHRIKE_LLM_MODEL=overlabbed/shrike-extractor  # or any OpenAI-compatible model
```

## Runtime Behavior

### Without ML Models
```
WARNING: ML dependencies (torch, transformers) not installed. 
Falling back to pattern-only mode.
```

Shrike continues to function normally:
- ✅ All format detection works
- ✅ Pattern-based extraction works (Tiers 0-1)
- ✅ Schema validation works
- ⚠️ Classification defaults to class_uid=0 (unclassified)
- ⚠️ NER extraction skipped (Tier 1.5a)
- ⚠️ LLM extraction skipped (Tiers 2-3)

### With ML Models
- ✅ Full 6-tier extraction pipeline
- ✅ Automatic OCSF class classification (98.9% accuracy)
- ✅ Named entity extraction
- ✅ LLM-assisted extraction for complex logs

## Performance Impact

| Mode | Throughput | Latency | Use Case |
|------|------------|---------|----------|
| **Pattern-only** | 10K+ events/sec | <5ms/log | High-volume log normalization |
| **ML-enabled** | 2K-5K events/sec | 50-200ms/log | Security analytics requiring classification |
| **ML + LLM** | 100-500 events/sec | 200-750ms/log | Complex/unseen log formats |

## Testing ML Features

To run tests that require ML models:
```bash
# Install ML dependencies
pip install -e ".[ml]"

# Download models
./scripts/download_models.sh

# Run full test suite
pytest tests/ -v

# Run only ML tests
pytest tests/ -v -k "classifier or ner"
```

Tests that don't require ML:
```bash
# Run pattern-only tests
pytest tests/ -v -m "not ml_required"
```

## Recommendations

- **Production deployment**: Use pattern-only mode for high throughput
- **Security analytics**: Enable ML classification for threat detection
- **Unknown formats**: Add LLM extraction for custom log types
- **Development**: Install full ML stack for testing all features
