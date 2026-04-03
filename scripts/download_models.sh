#!/usr/bin/env bash
# Download Shrike ML models from GitHub Releases.
#
# Usage:
#   ./scripts/download_models.sh
#
# Models are downloaded to models/ in the repo root.
# If git-lfs is available, tries 'git lfs pull' first.

set -euo pipefail

REPO="overlabbed-com/shrike"
TAG="models-v0.1.0"
TARBALL="shrike-models-v0.1.0.tar.gz"
MODELS_DIR="$(cd "$(dirname "$0")/.." && pwd)/models"

# Check if models are already present (not LFS pointers)
check_model() {
    local path="$1"
    if [ -f "$path" ] && ! head -c 50 "$path" | grep -q "git-lfs"; then
        return 0  # Real model file
    fi
    return 1  # Missing or LFS pointer
}

if check_model "$MODELS_DIR/ocsf-classifier/model.safetensors" && \
   check_model "$MODELS_DIR/shrike-ner/model.safetensors"; then
    echo "Models already downloaded."
    exit 0
fi

echo "Shrike models not found or are Git LFS pointers."

# Try git lfs pull first (fastest if LFS is set up)
if command -v git-lfs >/dev/null 2>&1 || git lfs version >/dev/null 2>&1; then
    echo "Trying 'git lfs pull'..."
    if git lfs pull 2>/dev/null; then
        if check_model "$MODELS_DIR/ocsf-classifier/model.safetensors"; then
            echo "Models downloaded via Git LFS."
            exit 0
        fi
    fi
    echo "Git LFS pull didn't work. Falling back to GitHub Release download."
fi

# Download from GitHub Releases
URL="https://github.com/${REPO}/releases/download/${TAG}/${TARBALL}"
echo "Downloading models from ${URL}..."

mkdir -p "$MODELS_DIR"

if command -v curl >/dev/null 2>&1; then
    curl -fSL --progress-bar "$URL" -o "/tmp/${TARBALL}"
elif command -v wget >/dev/null 2>&1; then
    wget -q --show-progress "$URL" -O "/tmp/${TARBALL}"
else
    echo "Error: neither curl nor wget found. Install one and retry." >&2
    exit 1
fi

echo "Extracting models..."
tar -xzf "/tmp/${TARBALL}" -C "$MODELS_DIR"
rm -f "/tmp/${TARBALL}"

# Verify
if check_model "$MODELS_DIR/ocsf-classifier/model.safetensors" && \
   check_model "$MODELS_DIR/shrike-ner/model.safetensors"; then
    echo "Models downloaded successfully."
    echo "  - ocsf-classifier (DistilBERT, 256MB)"
    echo "  - shrike-ner (SecureBERT, 571MB)"
else
    echo "Error: models not found after extraction." >&2
    exit 1
fi
