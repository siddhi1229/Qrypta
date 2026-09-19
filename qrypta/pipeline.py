"""Pipeline orchestration module for Qrypta."""

import tempfile
from pathlib import Path
from typing import Dict, Any, Union

from qrypta.scanner.engine import scan_repository
from qrypta.inventory.builder import build_inventory
from qrypta.context.analyzer import analyze_context
from qrypta.risk.engine import calculate_risk
from qrypta.pqc.mapper import map_to_pqc
from qrypta.migration.planner import create_migration_plan
from qrypta.patch.generator import generate_patches
from qrypta.validate.validator import validate_patches


def run_pipeline(repository_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Run the complete deterministic Qrypta analysis, migration, patching, and validation pipeline.

    Stages executed in exact order:
    1. scan_repository(repository_path)
    2. build_inventory(findings)
    3. analyze_context(findings)
    4. calculate_risk(context_findings)
    5. map_to_pqc(risk_findings)
    6. create_migration_plan(pqc_findings)
    7. generate_patches(repository_path, migration_findings)
    8. validate_patches(repository_path, patch_result)

    Returns:
        {
            "inventory": ...,
            "findings": ...,
            "risk": ...,
            "pqc": ...,
            "migration": ...,
            "patch": ...,
            "validation": ...
        }
    """
    repo_path = Path(repository_path).resolve()

    # Stage 1: Scan repository
    findings = scan_repository(repo_path)

    # Stage 2: Build inventory
    inventory = build_inventory(findings)

    # Stage 3: Analyze context
    context_findings = analyze_context(findings)

    # Stage 4: Calculate risk
    risk_findings = calculate_risk(context_findings)

    # Stage 5: Map to PQC
    pqc_findings = map_to_pqc(risk_findings)

    # Stage 6: Create migration plan
    migration_findings = create_migration_plan(pqc_findings)

    # Stages 7 & 8: Generate patches in temporary sandbox and validate
    with tempfile.TemporaryDirectory() as sandbox_dir:
        patch_result = generate_patches(repo_path, migration_findings, sandbox_path=sandbox_dir)
        validation_result = validate_patches(repo_path, patch_result)

    return {
        "inventory": inventory,
        "findings": findings,
        "risk": risk_findings,
        "pqc": pqc_findings,
        "migration": migration_findings,
        "patch": patch_result,
        "validation": validation_result,
    }
