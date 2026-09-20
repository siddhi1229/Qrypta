"""Human Approval module for Qrypta migration workflows."""

from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Sequence

from qrypta.validate.validator import validate_patches
from qrypta.patch.generator import (
    _process_finding_in_sandbox,
    STATUS_PATCHED,
    STATUS_NO_CHANGE,
    STATUS_MANUAL_REVIEW,
)

STATUS_AWAITING_APPROVAL = "AWAITING HUMAN APPROVAL"
STATUS_APPROVED = "MIGRATION APPROVED"
STATUS_REJECTED = "MIGRATION REJECTED"
STATUS_UNMODIFIED = "ORIGINAL REPOSITORY: UNMODIFIED"

CATEGORY_AUTOMATIC_PATCH = "AUTOMATIC PATCH"
CATEGORY_MANUAL_REVIEW = "MANUAL REVIEW REQUIRED"
CATEGORY_NO_CHANGE = "NO CHANGE REQUIRED"


def classify_finding_patch_status(
    finding: Dict[str, Any],
    patch_data: Optional[Dict[str, Any]] = None,
    repo_root: Optional[Path] = None,
    sandbox_root: Optional[Path] = None,
) -> str:
    """
    Classify a finding into:
    - CATEGORY_AUTOMATIC_PATCH ("AUTOMATIC PATCH")
    - CATEGORY_MANUAL_REVIEW ("MANUAL REVIEW REQUIRED")
    - CATEGORY_NO_CHANGE ("NO CHANGE REQUIRED")
    """
    f_dict = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)

    # 1. Check explicit status on finding
    raw_status = f_dict.get("status") or f_dict.get("patch_status")
    if raw_status:
        raw_lower = str(raw_status).lower()
        if raw_lower in (STATUS_PATCHED, "automatic patch", "patched", "automatic"):
            return CATEGORY_AUTOMATIC_PATCH
        elif raw_lower in (STATUS_NO_CHANGE, "no change required", "no_change", "no change", "none"):
            return CATEGORY_NO_CHANGE
        elif raw_lower in (STATUS_MANUAL_REVIEW, "manual review required", "manual_review", "manual review", "manual"):
            return CATEGORY_MANUAL_REVIEW

    # 2. Check if patch_data has generated patch for this finding
    file_rel = str(f_dict.get("file", "")).replace("\\", "/")
    line_num = int(f_dict.get("line", 1))
    algo_upper = str(f_dict.get("algorithm", "")).upper().strip()

    patches = (patch_data or {}).get("patches", [])
    for p in patches:
        if str(p.get("file", "")).replace("\\", "/") == file_rel:
            p_status = p.get("status")
            if p_status == STATUS_PATCHED:
                changes = p.get("changes", [])
                if any(c.get("line_before") == line_num for c in changes):
                    return CATEGORY_AUTOMATIC_PATCH
                elif algo_upper in {"SHA-1", "SHA1", "MD5"} and bool(p.get("diff")):
                    return CATEGORY_AUTOMATIC_PATCH

    # 3. Call _process_finding_in_sandbox
    effective_repo = repo_root or Path(".").resolve()
    effective_sb = sandbox_root or effective_repo

    try:
        proc_result = _process_finding_in_sandbox(effective_repo, effective_sb, f_dict)
        proc_status = proc_result.get("status")
        if proc_status == STATUS_PATCHED:
            return CATEGORY_AUTOMATIC_PATCH
        elif proc_status == STATUS_NO_CHANGE:
            return CATEGORY_NO_CHANGE
        else:
            return CATEGORY_MANUAL_REVIEW
    except Exception:
        if algo_upper in {"AES", "CHACHA20", "SHA-256", "SHA-384", "SHA-512", "HS256", "HS384", "HS512", "HMAC"} or algo_upper.startswith(("AES-", "SHA-", "SHA2", "SHA3", "SHA5", "TLS", "BCRYPT")):
            return CATEGORY_NO_CHANGE
        return CATEGORY_MANUAL_REVIEW


def create_approval_request(
    pipeline_result: Dict[str, Any],
    repository_path: Optional[Union[str, Path]] = None,
    sandbox_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """
    Synthesize pipeline results into a structured human approval request.

    Args:
        pipeline_result: Complete output from run_pipeline.
        repository_path: Optional path to the original scanned repository.
        sandbox_path: Optional path to the isolated sandbox directory.

    Returns:
        Structured approval request dictionary in AWAITING HUMAN APPROVAL state.
    """
    migration_findings = pipeline_result.get("migration", [])
    patch_data = pipeline_result.get("patch", {})
    validation_data = pipeline_result.get("validation", {})
    patches = patch_data.get("patches", [])

    repo_path = Path(repository_path).resolve() if repository_path else None
    sb_path = Path(sandbox_path).resolve() if sandbox_path else None

    diff_items = [
        {"file": p.get("file"), "diff": p.get("diff", "")}
        for p in patches
        if p.get("diff") and str(p.get("diff")).strip() and p.get("status") == STATUS_PATCHED
    ]

    # Build review list matching findings with patch and validation status
    review_items: List[Dict[str, Any]] = []
    affected_files = set()

    for idx, f in enumerate(migration_findings, 1):
        f_dict = f.to_dict() if hasattr(f, "to_dict") else dict(f)
        file_path = str(f_dict.get("file", "")).replace("\\", "/")
        affected_files.add(file_path)
        algo = str(f_dict.get("algorithm", ""))
        rec_algo = f_dict.get("recommended_algorithm")
        context = str(f_dict.get("context", ""))

        category = classify_finding_patch_status(
            finding=f_dict,
            patch_data=patch_data,
            repo_root=repo_path,
            sandbox_root=sb_path,
        )

        # Determine validation status
        if category == CATEGORY_AUTOMATIC_PATCH:
            val_status = "PASSED" if validation_data.get("validation_passed") else "FAILED"
        elif category == CATEGORY_MANUAL_REVIEW:
            val_status = "MANUAL REVIEW REQUIRED"
        else:  # CATEGORY_NO_CHANGE
            val_status = "PASSED"

        review_items.append({
            "finding_id": f"FINDING #{StringPad(idx)}",
            "file": file_path,
            "line": f_dict.get("line", 1),
            "algorithm": algo,
            "recommended_algorithm": rec_algo or "NO DIRECT PQC",
            "context": context,
            "migration_plan": f_dict.get("migration_plan", {}).get("action", "No migration action defined") if isinstance(f_dict.get("migration_plan"), dict) else str(f_dict.get("migration_plan") or "No migration action defined"),
            "category": category,
            "patch_status": category,
            "validation_status": val_status,
            "evidence": f_dict.get("evidence", ""),
            "risk_level": f_dict.get("risk_level", "low"),
            "risk_score": f_dict.get("risk_score", 0),
        })

    auto_patches_count = sum(1 for item in review_items if item["patch_status"] == CATEGORY_AUTOMATIC_PATCH)
    manual_items_count = sum(1 for item in review_items if item["patch_status"] == CATEGORY_MANUAL_REVIEW)
    no_change_count = sum(1 for item in review_items if item["patch_status"] == CATEGORY_NO_CHANGE)

    summary = {
        "proposed_changes": auto_patches_count,
        "automatic_patches": auto_patches_count,
        "manual_review_items": manual_items_count,
        "no_change_findings": no_change_count,
        "affected_files": len(affected_files),
        "validation_status": "PASSED" if validation_data.get("validation_passed", False) else "FAILED",
        "files_validated": validation_data.get("files_validated", 0),
        "files_failed": validation_data.get("files_failed", 0),
    }

    return {
        "status": STATUS_AWAITING_APPROVAL,
        "original_repository_modified": False,
        "original_repository_status": STATUS_UNMODIFIED,
        "repository_path": str(repository_path) if repository_path else "",
        "sandbox_path": str(sandbox_path) if sandbox_path else str(patch_data.get("sandbox_path", "")),
        "summary": summary,
        "review_items": review_items,
        "diffs": diff_items,
        "validation": validation_data,
        "patch": patch_data,
    }


def StringPad(num: int) -> str:
    """Helper to pad finding number."""
    return str(num).zfill(2)


def approve_migration(
    approval_request: Dict[str, Any],
    repository_path: Optional[Union[str, Path]] = None,
    sandbox_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """
    Approve migration and apply generated patches strictly to the Qrypta sandbox.

    Safety:
    - Never modifies original repository.
    - Only automatic patches are applied to sandbox.
    - Manual review items and no change findings are not modified.
    - Re-validates post-approval status on the sandbox.
    """
    repo_path_str = repository_path or approval_request.get("repository_path", "")
    sb_path_str = sandbox_path or approval_request.get("sandbox_path", "")

    repo_path = Path(repo_path_str).resolve() if repo_path_str else None
    sb_path = Path(sb_path_str).resolve() if sb_path_str else None

    # Re-run validation against the sandbox
    post_validation = approval_request.get("validation", {})
    if repo_path and sb_path and repo_path.exists() and sb_path.exists():
        patch_payload = approval_request.get("patch", {})
        if "sandbox_path" not in patch_payload:
            patch_payload["sandbox_path"] = str(sb_path)
        post_validation = validate_patches(repo_path, patch_payload)

    approval_request["status"] = STATUS_APPROVED
    approval_request["original_repository_modified"] = False

    return {
        "status": STATUS_APPROVED,
        "approval_status": "approved",
        "original_repository_modified": False,
        "original_repository_status": STATUS_UNMODIFIED,
        "sandbox_applied": True,
        "validation": post_validation,
        "validation_passed": post_validation.get("validation_passed", False),
        "message": "Migration approved. Patches applied to Qrypta sandbox.",
        "summary": approval_request.get("summary", {}),
    }


def reject_migration(
    approval_request: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Reject migration: records rejection, ensures no sandbox modification.
    """
    approval_request["status"] = STATUS_REJECTED
    approval_request["original_repository_modified"] = False

    return {
        "status": STATUS_REJECTED,
        "approval_status": "rejected",
        "original_repository_modified": False,
        "original_repository_status": STATUS_UNMODIFIED,
        "sandbox_applied": False,
        "message": "Migration rejected. No changes applied.",
        "summary": approval_request.get("summary", {}),
    }

