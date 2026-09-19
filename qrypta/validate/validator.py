"""Patch Validator module for Qrypta."""

import ast
import difflib
from pathlib import Path
from typing import List, Dict, Any, Union, Sequence, Optional

CHECK_STATUS_PASSED = "passed"
CHECK_STATUS_FAILED = "failed"
CHECK_STATUS_MANUAL_REVIEW = "manual_review"
CHECK_STATUS_SKIPPED = "skipped"


def _generate_unified_diff(original_text: str, patched_text: str) -> str:
    """Generate standard unified diff containing '--- original' and '+++ patched'."""
    orig_lines = original_text.splitlines(keepends=True)
    patch_lines = patched_text.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines,
        patch_lines,
        fromfile="original",
        tofile="patched",
    )
    return "".join(diff)


def validate_patches(
    repository_path: Union[str, Path],
    patch_result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Validate proposed changes in the temporary sandbox without modifying original repository.

    Args:
        repository_path: Path to original repository.
        patch_result: Patch result dictionary produced by Module 7.

    Returns:
        {
            "validation_passed": bool,
            "original_repository_modified": bool,
            "checks": List[Dict[str, str]],
            "files_validated": int,
            "files_failed": int,
            "manual_review_required": bool
        }
    """
    repo_root = Path(repository_path).resolve()
    sandbox_path_str = str(patch_result.get("sandbox_path", ""))
    sandbox_path = Path(sandbox_path_str).resolve() if sandbox_path_str else None

    checks: List[Dict[str, str]] = []
    failed_files = set()
    validated_files = set()
    manual_review_required = False
    original_repo_modified = False

    # Check 1: Original repository existence
    if not repo_root.exists() or not repo_root.is_dir():
        checks.append({
            "name": "original_repository_existence",
            "status": CHECK_STATUS_FAILED,
            "message": f"Original repository at '{repo_root}' does not exist or is not a directory",
        })
        return {
            "validation_passed": False,
            "original_repository_modified": False,
            "checks": checks,
            "files_validated": 0,
            "files_failed": 0,
            "manual_review_required": False,
        }

    # Check 2: Sandbox existence
    if not sandbox_path or not sandbox_path.exists() or not sandbox_path.is_dir():
        checks.append({
            "name": "sandbox_existence",
            "status": CHECK_STATUS_FAILED,
            "message": f"Sandbox directory '{sandbox_path_str}' does not exist or is unavailable",
        })
        return {
            "validation_passed": False,
            "original_repository_modified": False,
            "checks": checks,
            "files_validated": 0,
            "files_failed": 0,
            "manual_review_required": False,
        }
    else:
        checks.append({
            "name": "sandbox_existence",
            "status": CHECK_STATUS_PASSED,
            "message": "Sandbox directory verified and accessible",
        })

    patches = patch_result.get("patches", [])

    for p in patches:
        file_rel = str(p.get("file", "")).replace("\\", "/")
        status = str(p.get("status", "")).lower().strip()
        diff_text = str(p.get("diff", ""))
        changes = p.get("changes", [])

        if file_rel:
            validated_files.add(file_rel)

        if status == "manual_review":
            manual_review_required = True
            checks.append({
                "name": f"manual_review:{file_rel}",
                "status": CHECK_STATUS_MANUAL_REVIEW,
                "message": f"Human review is required before migration for finding in {file_rel}",
            })
            # Consistency: diff must be empty
            if diff_text.strip():
                checks.append({
                    "name": f"patch_consistency:{file_rel}",
                    "status": CHECK_STATUS_FAILED,
                    "message": f"Manual review finding in {file_rel} should have empty diff",
                })
                failed_files.add(file_rel)
            continue

        if status == "no_change":
            checks.append({
                "name": f"no_change:{file_rel}",
                "status": CHECK_STATUS_PASSED,
                "message": f"No cryptographic changes required for {file_rel}",
            })
            # Consistency: diff must be empty
            if diff_text.strip():
                checks.append({
                    "name": f"patch_consistency:{file_rel}",
                    "status": CHECK_STATUS_FAILED,
                    "message": f"No-change finding in {file_rel} should have empty diff",
                })
                failed_files.add(file_rel)
            continue

        if status == "patched":
            orig_file = repo_root / file_rel
            sb_file = sandbox_path / file_rel

            # 1. Original repository integrity check
            if not orig_file.exists() or not orig_file.is_file():
                checks.append({
                    "name": f"original_repo_integrity:{file_rel}",
                    "status": CHECK_STATUS_FAILED,
                    "message": f"Original file {file_rel} missing from original repository",
                })
                failed_files.add(file_rel)
                original_repo_modified = True
            elif not sb_file.exists() or not sb_file.is_file():
                checks.append({
                    "name": f"sandbox_file_existence:{file_rel}",
                    "status": CHECK_STATUS_FAILED,
                    "message": f"Patched file {file_rel} missing from sandbox",
                })
                failed_files.add(file_rel)
            else:
                orig_content = orig_file.read_text(encoding="utf-8", errors="replace")
                sb_content = sb_file.read_text(encoding="utf-8", errors="replace")
                recomputed_diff = _generate_unified_diff(orig_content, sb_content)

                if recomputed_diff != diff_text:
                    checks.append({
                        "name": f"original_repo_integrity:{file_rel}",
                        "status": CHECK_STATUS_FAILED,
                        "message": f"Original file {file_rel} differs unexpectedly from diff snapshot",
                    })
                    failed_files.add(file_rel)
                    original_repo_modified = True
                else:
                    checks.append({
                        "name": f"original_repo_integrity:{file_rel}",
                        "status": CHECK_STATUS_PASSED,
                        "message": f"Original file {file_rel} verified intact and unmodified",
                    })

                # 2. Patch consistency: diff must be non-empty
                if not diff_text.strip():
                    checks.append({
                        "name": f"patch_consistency:{file_rel}",
                        "status": CHECK_STATUS_FAILED,
                        "message": f"Patched file {file_rel} has empty diff",
                    })
                    failed_files.add(file_rel)
                else:
                    checks.append({
                        "name": f"patch_consistency:{file_rel}",
                        "status": CHECK_STATUS_PASSED,
                        "message": f"Patched file {file_rel} has valid diff",
                    })

                # 3. Python syntax validation (AST parsing)
                if file_rel.endswith(".py"):
                    try:
                        ast.parse(sb_content)
                        checks.append({
                            "name": f"syntax_validation:{file_rel}",
                            "status": CHECK_STATUS_PASSED,
                            "message": f"Python AST parsing succeeded for {file_rel}",
                        })
                    except SyntaxError as e:
                        checks.append({
                            "name": f"syntax_validation:{file_rel}",
                            "status": CHECK_STATUS_FAILED,
                            "message": f"Python AST syntax error in {file_rel}: {e}",
                        })
                        failed_files.add(file_rel)

                # 4. Hash migration static validation
                is_hash_patch = any("hashlib" in str(c.get("description", "")) for c in changes)
                if is_hash_patch:
                    # Check that hashlib.sha256( is present
                    has_sha256 = "hashlib.sha256(" in sb_content
                    # Check that targeted lines no longer have hashlib.sha1( or hashlib.md5(
                    lines = sb_content.splitlines()
                    targeted_clean = True
                    for c in changes:
                        lb = c.get("line_before", 0)
                        if 1 <= lb <= len(lines):
                            target_line = lines[lb - 1]
                            if "hashlib.sha1" in str(c.get("description", "")) and "hashlib.sha1(" in target_line:
                                targeted_clean = False
                            if "hashlib.md5" in str(c.get("description", "")) and "hashlib.md5(" in target_line:
                                targeted_clean = False

                    if has_sha256 and targeted_clean:
                        checks.append({
                            "name": f"hash_migration_validation:{file_rel}",
                            "status": CHECK_STATUS_PASSED,
                            "message": f"Static hash validation verified for {file_rel} (hashlib.sha256 present, legacy calls removed)",
                        })
                    else:
                        checks.append({
                            "name": f"hash_migration_validation:{file_rel}",
                            "status": CHECK_STATUS_FAILED,
                            "message": f"Static hash validation failed for {file_rel} (legacy call still present or sha256 missing)",
                        })
                        failed_files.add(file_rel)

    # Sort checks deterministically by name, status, message
    checks.sort(key=lambda c: (str(c.get("name", "")), str(c.get("status", "")), str(c.get("message", ""))))

    has_any_failure = any(c.get("status") == CHECK_STATUS_FAILED for c in checks)
    validation_passed = not has_any_failure

    return {
        "validation_passed": validation_passed,
        "original_repository_modified": original_repo_modified,
        "checks": checks,
        "files_validated": len(validated_files),
        "files_failed": len(failed_files),
        "manual_review_required": manual_review_required,
    }
