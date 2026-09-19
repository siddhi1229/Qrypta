"""Patch Generator module for Qrypta."""

import difflib
import shutil
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Union, Sequence, Optional

STATUS_PATCHED = "patched"
STATUS_NO_CHANGE = "no_change"
STATUS_MANUAL_REVIEW = "manual_review"

IGNORED_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
}

ASYMMETRIC_SIGNATURE_ALGORITHMS = {
    "RSA",
    "ECDSA",
    "ED25519",
    "EDDSA",
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
}

ASYMMETRIC_KEX_ALGORITHMS = {
    "RSA",
    "ECDH",
    "DH",
    "DIFFIE-HELLMAN",
}

MODERN_SYMMETRIC_ALGORITHMS = {
    "AES",
    "AES-128",
    "AES-192",
    "AES-256",
    "AES-GCM",
    "AES-CBC",
    "AES-CTR",
    "CHACHA20",
    "CHACHA20-POLY1305",
}

SECURE_HASH_ALGORITHMS = {
    "SHA-256",
    "SHA256",
    "SHA-384",
    "SHA384",
    "SHA-512",
    "SHA512",
    "HS256",
    "HS384",
    "HS512",
}


def _is_safe_relative_path(repo_root: Path, file_path_str: str) -> bool:
    """Check whether a relative file path is safe and inside the repository."""
    if not file_path_str:
        return False
    try:
        raw_path = Path(file_path_str)
        if ".." in raw_path.parts:
            return False
        if raw_path.is_absolute():
            resolved = raw_path.resolve()
        else:
            resolved = (repo_root / file_path_str).resolve()

        if not resolved.is_relative_to(repo_root):
            return False

        rel_parts = resolved.relative_to(repo_root).parts
        if any(part in IGNORED_DIRS for part in rel_parts):
            return False

        return True
    except Exception:
        return False


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



def _process_finding_in_sandbox(
    repo_root: Path,
    sandbox_root: Path,
    finding: Dict[str, Any],
) -> Dict[str, Any]:
    """Process a single finding inside the sandbox and generate patch result."""
    file_rel = str(finding.get("file", "")).replace("\\", "/")
    algo_upper = str(finding.get("algorithm", "")).upper().strip()
    rec_algo = str(finding.get("recommended_algorithm", "") or "").strip()
    mig_type = str(finding.get("migration_type", "")).lower().strip()

    # Safety check on file path
    if not _is_safe_relative_path(repo_root, file_rel):
        return {
            "file": file_rel,
            "status": STATUS_MANUAL_REVIEW,
            "changes": [],
            "diff": "",
        }

    # 1. Modern symmetric cryptography -> no_change
    if (
        algo_upper in MODERN_SYMMETRIC_ALGORITHMS
        or algo_upper.startswith(("AES", "CHACHA20"))
    ):
        return {
            "file": file_rel,
            "status": STATUS_NO_CHANGE,
            "changes": [],
            "diff": "",
        }

    # 2. Secure hash / HMAC -> no_change
    if (
        algo_upper in SECURE_HASH_ALGORITHMS
        or algo_upper.startswith(("SHA-256", "SHA-384", "SHA-512", "SHA256", "SHA384", "SHA512", "HS256", "HS384", "HS512", "HMAC"))
    ):
        return {
            "file": file_rel,
            "status": STATUS_NO_CHANGE,
            "changes": [],
            "diff": "",
        }

    # 3. Legacy cipher (DES / 3DES) -> manual_review
    if algo_upper in {"DES", "3DES", "TRIPLEDES"} or algo_upper.startswith(("DES", "3DES", "TRIPLEDES")):
        return {
            "file": file_rel,
            "status": STATUS_MANUAL_REVIEW,
            "changes": [],
            "diff": "",
        }

    # 4. Asymmetric signature -> manual_review
    if rec_algo == "ML-DSA" or algo_upper in ASYMMETRIC_SIGNATURE_ALGORITHMS or algo_upper.startswith(("RSA", "ECDSA", "ED25519", "EDDSA", "RS", "ES")):
        return {
            "file": file_rel,
            "status": STATUS_MANUAL_REVIEW,
            "changes": [],
            "diff": "",
        }

    # 5. Asymmetric key exchange -> manual_review
    if rec_algo == "ML-KEM" or algo_upper in ASYMMETRIC_KEX_ALGORITHMS or algo_upper.startswith(("ECDH", "DH", "DIFFIE-HELLMAN")):
        return {
            "file": file_rel,
            "status": STATUS_MANUAL_REVIEW,
            "changes": [],
            "diff": "",
        }

    # 6. Legacy hashes: SHA-1 / MD5 Python hashlib transformations
    if algo_upper in {"SHA-1", "SHA1", "MD5"}:
        sandbox_file = sandbox_root / file_rel
        if sandbox_file.exists() and sandbox_file.is_file():
            try:
                with open(sandbox_file, "r", encoding="utf-8", errors="replace") as f:
                    original_content = f.read()

                lines = original_content.splitlines(keepends=True)
                new_lines = []
                changes = []

                for idx, line in enumerate(lines):
                    new_line = line
                    stripped = line.strip()

                    # Only transform non-comment lines containing exact hashlib function calls
                    if not stripped.startswith("#"):
                        if algo_upper in {"SHA-1", "SHA1"} and "hashlib.sha1(" in line:
                            new_line = line.replace("hashlib.sha1(", "hashlib.sha256(")
                            changes.append({
                                "description": "Replace hashlib.sha1 with hashlib.sha256",
                                "line_before": idx + 1,
                                "line_after": idx + 1,
                            })
                        elif algo_upper == "MD5" and "hashlib.md5(" in line:
                            new_line = line.replace("hashlib.md5(", "hashlib.sha256(")
                            changes.append({
                                "description": "Replace hashlib.md5 with hashlib.sha256",
                                "line_before": idx + 1,
                                "line_after": idx + 1,
                            })

                    new_lines.append(new_line)

                if changes:
                    patched_content = "".join(new_lines)
                    with open(sandbox_file, "w", encoding="utf-8") as f:
                        f.write(patched_content)

                    diff_text = _generate_unified_diff(original_content, patched_content)
                    return {
                        "file": file_rel,
                        "status": STATUS_PATCHED,
                        "changes": changes,
                        "diff": diff_text,
                    }
                else:
                    return {
                        "file": file_rel,
                        "status": STATUS_MANUAL_REVIEW,
                        "changes": [],
                        "diff": "",
                    }
            except Exception:
                return {
                    "file": file_rel,
                    "status": STATUS_MANUAL_REVIEW,
                    "changes": [],
                    "diff": "",
                }

    # 7. Default fallback -> manual_review
    return {
        "file": file_rel,
        "status": STATUS_MANUAL_REVIEW,
        "changes": [],
        "diff": "",
    }


def generate_patches(
    repository_path: Union[str, Path],
    findings: Sequence[Union[Dict[str, Any], Any]],
) -> Dict[str, Any]:
    """
    Generate proposed source-code changes from Migration Plan findings in a temporary sandbox.

    Args:
        repository_path: Path to the root of the original repository.
        findings: Sequence of finding dictionaries containing migration plan metadata.

    Returns:
        {
            "sandbox_path": str,
            "original_repository_modified": False,
            "files_changed": int,
            "patches": List[Dict[str, Any]]
        }
    """
    repo_root = Path(repository_path).resolve()
    patches: List[Dict[str, Any]] = []
    recorded_sandbox_path = ""
    changed_files = set()

    with tempfile.TemporaryDirectory() as sandbox_dir:
        sandbox_root = Path(sandbox_dir)
        recorded_sandbox_path = str(sandbox_root)

        # Copy original repository content to sandbox (ignoring unwanted directories)
        if repo_root.exists() and repo_root.is_dir():
            try:
                shutil.copytree(
                    repo_root,
                    sandbox_root,
                    dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"),
                )
            except Exception:
                pass

        for item in findings:
            if hasattr(item, "to_dict"):
                d = item.to_dict()
            elif isinstance(item, dict):
                d = dict(item)
            else:
                continue

            patch_result = _process_finding_in_sandbox(repo_root, sandbox_root, d)
            patches.append(patch_result)

            if patch_result["status"] == STATUS_PATCHED:
                changed_files.add(patch_result["file"])

    # Deterministically sort patches by file, status
    patches.sort(key=lambda p: (
        str(p.get("file", "")),
        int(p.get("changes", [{}])[0].get("line_before", 0) if p.get("changes") else 0),
        str(p.get("status", "")),
    ))

    return {
        "sandbox_path": recorded_sandbox_path,
        "original_repository_modified": False,
        "files_changed": len(changed_files),
        "patches": patches,
    }
