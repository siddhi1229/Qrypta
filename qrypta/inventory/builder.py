"""Crypto Inventory builder module for Qrypta."""

from typing import List, Dict, Any, Union, Sequence, Optional
from qrypta.scanner.models import Finding


def _normalize_finding(item: Union[Finding, Dict[str, Any]]) -> Dict[str, Any]:
    """Convert Finding object or raw dictionary to standard normalized finding dict."""
    if hasattr(item, "to_dict"):
        return item.to_dict()
    elif isinstance(item, dict):
        variant_val = item.get("variant")
        lib_val = item.get("library")
        return {
            "algorithm": str(item["algorithm"]),
            "variant": str(variant_val) if variant_val is not None else None,
            "primitive": str(item["primitive"]),
            "usage": str(item.get("usage", "")),
            "file": str(item["file"]),
            "line": int(item["line"]),
            "evidence": str(item["evidence"]),
            "library": str(lib_val) if lib_val is not None else None,
            "confidence": round(float(item["confidence"]), 2),
        }
    else:
        raise TypeError(f"Expected Finding or dict, got {type(item).__name__}")


def build_inventory(findings: Sequence[Union[Finding, Dict[str, Any]]]) -> Dict[str, Any]:
    """
    Build a normalized, deterministic cryptographic inventory from Scanner findings.

    Args:
        findings: Sequence of Finding objects or finding dictionaries.

    Returns:
        Structured dictionary matching the Qrypta inventory schema:
        {
          "summary": {
            "total_findings": int,
            "unique_algorithms": int,
            "unique_primitives": int
          },
          "algorithms": [
            {
              "algorithm": str,
              "variants": List[str],
              "primitive": str,
              "occurrence_count": int,
              "libraries": List[str],
              "locations": [
                {
                  "file": str,
                  "line": int,
                  "evidence": str,
                  "confidence": float
                }
              ]
            }
          ]
        }
    """
    if not findings:
        return {
            "summary": {
                "total_findings": 0,
                "unique_algorithms": 0,
                "unique_primitives": 0,
            },
            "algorithms": [],
        }

    # 1. Deduplicate findings that are completely identical across all fields
    deduped_findings: List[Dict[str, Any]] = []
    seen_keys = set()

    for item in findings:
        f = _normalize_finding(item)
        dedup_key = (
            f["algorithm"],
            f["variant"],
            f["primitive"],
            f["usage"],
            f["file"],
            f["line"],
            f["evidence"],
            f["library"],
            f["confidence"],
        )
        if dedup_key not in seen_keys:
            seen_keys.add(dedup_key)
            deduped_findings.append(f)

    # 2. Extract unique summary counts
    unique_algos = sorted(list({f["algorithm"] for f in deduped_findings}))
    unique_primitives = sorted(list({f["primitive"] for f in deduped_findings}))

    summary = {
        "total_findings": len(deduped_findings),
        "unique_algorithms": len(unique_algos),
        "unique_primitives": len(unique_primitives),
    }

    # 3. Group findings by algorithm
    grouped_by_algo: Dict[str, List[Dict[str, Any]]] = {}
    for f in deduped_findings:
        algo_name = f["algorithm"]
        if algo_name not in grouped_by_algo:
            grouped_by_algo[algo_name] = []
        grouped_by_algo[algo_name].append(f)

    algorithms_list: List[Dict[str, Any]] = []

    for algo_name in sorted(grouped_by_algo.keys()):
        group = grouped_by_algo[algo_name]

        # Extract unique variants sorted alphabetically (omitting None)
        variants = sorted(list({f["variant"] for f in group if f["variant"] is not None}))

        # Extract unique libraries sorted alphabetically (omitting None)
        libraries = sorted(list({f["library"] for f in group if f["library"] is not None}))

        # Determine primary primitive for the algorithm
        primitive = group[0]["primitive"]

        # Collect and sort locations by file path, then line number
        locations = []
        for f in group:
            locations.append(
                {
                    "file": f["file"],
                    "line": f["line"],
                    "evidence": f["evidence"],
                    "confidence": f["confidence"],
                }
            )

        locations.sort(key=lambda loc: (loc["file"], loc["line"]))

        algorithms_list.append(
            {
                "algorithm": algo_name,
                "variants": variants,
                "primitive": primitive,
                "occurrence_count": len(group),
                "libraries": libraries,
                "locations": locations,
            }
        )

    return {
        "summary": summary,
        "algorithms": algorithms_list,
    }
