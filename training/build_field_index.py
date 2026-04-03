#!/usr/bin/env python3
"""Build the embedding index for OCSF field name mapping.

Loads data/field_aliases.json, embeds all 110 field names with all-MiniLM-L6-v2,
saves to data/field_embeddings.npz, then tests with unseen field names.

Usage:
    python scripts/build_field_index.py
"""

import sys
from pathlib import Path

# Add project root to path so we can import shrike
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from shrike.extractor.embedding_field_mapper import EmbeddingFieldMapper, _normalize_field_name


def main():
    data_dir = project_root / "data"
    aliases_path = data_dir / "field_aliases.json"
    index_path = data_dir / "field_embeddings.npz"

    if not aliases_path.exists():
        print(f"ERROR: {aliases_path} not found")
        sys.exit(1)

    print("=" * 70)
    print("Building OCSF Field Embedding Index")
    print("=" * 70)

    # Build index
    mapper = EmbeddingFieldMapper(aliases_path=aliases_path, index_path=index_path)
    saved_path = mapper.build_index()

    size_kb = saved_path.stat().st_size / 1024
    print(f"\nIndex saved: {saved_path}")
    print(f"  Entries: {mapper.entry_count}")
    print(f"  Unique OCSF paths: {mapper.unique_ocsf_paths}")
    print(f"  File size: {size_kb:.1f} KB")

    # Test with unseen field names
    print("\n" + "=" * 70)
    print("Testing with unseen field names")
    print("=" * 70)

    test_cases = [
        ("sourceAddress", "src_endpoint.ip"),
        ("targetUserName", "user"),
        ("processName", "process.name"),
        ("destinationPort", "dst_endpoint.port"),
        ("eventAction", "activity_name"),
        ("logTimestamp", "time"),
        ("threatName", "finding_info.title"),
        ("hostName", "device.hostname"),
        # Additional interesting test cases
        ("remoteIP", "src_endpoint.ip"),
        ("parentProcessId", "process.parent_process.pid"),
        ("fileHash", "file.hashes.value"),
        ("httpMethod", "http_request.http_method"),
        ("dnsQueryName", "query.hostname"),
        ("cloudRegion", "cloud.region"),
        ("userAgent", "http_request.user_agent"),
        ("networkProtocol", "connection_info.protocol_name"),
    ]

    correct = 0
    total = len(test_cases)

    for vendor_field, expected_ocsf in test_cases:
        ocsf_path, score = mapper.map_field(vendor_field)
        normalized = _normalize_field_name(vendor_field)
        match = "PASS" if ocsf_path == expected_ocsf else "FAIL"
        if ocsf_path == expected_ocsf:
            correct += 1

        print(f"\n  {vendor_field} -> \"{normalized}\"")
        print(f"    Predicted: {ocsf_path or '(none)'} (score: {score:.3f})")
        print(f"    Expected:  {expected_ocsf}")
        print(f"    Result:    {match}")

        # Show top-3 for failures
        if match == "FAIL":
            top3 = mapper.map_field_topk(vendor_field, k=3)
            print("    Top 3 matches:")
            for known, ocsf, s in top3:
                flag = " <-- expected" if ocsf == expected_ocsf else ""
                print(f"      {s:.3f}  {known} -> {ocsf}{flag}")

    print(f"\n{'=' * 70}")
    print(f"Results: {correct}/{total} correct ({100 * correct / total:.0f}%)")
    print(f"{'=' * 70}")

    # Verify index can be loaded from disk
    print("\nVerifying index loads from disk...")
    mapper2 = EmbeddingFieldMapper(aliases_path=aliases_path, index_path=index_path)
    ocsf_path, score = mapper2.map_field("sourceAddress")
    print(f"  sourceAddress -> {ocsf_path} (score: {score:.3f})")
    assert ocsf_path == "src_endpoint.ip", f"Expected src_endpoint.ip, got {ocsf_path}"
    print("  Disk load verification: PASS")


if __name__ == "__main__":
    main()
