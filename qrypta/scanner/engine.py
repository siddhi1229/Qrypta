"""Qrypta unified repository scanner engine."""

import os
from pathlib import Path
from typing import List, Union, Set

from qrypta.scanner.models import Finding
from qrypta.scanner.python_scanner import scan_python_file
from qrypta.scanner.js_ts_scanner import scan_js_ts_file
from qrypta.scanner.rules import IGNORED_DIRECTORIES

# Supported file extensions
PYTHON_EXTENSIONS: Set[str] = {".py"}
JS_TS_EXTENSIONS: Set[str] = {
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
}


def should_ignore_path(path: Path) -> bool:
    """Check if any segment in the path is in the ignored directory list."""
    for part in path.parts:
        if part in IGNORED_DIRECTORIES:
            return True
    return False


def scan_repository(repo_path: Union[str, Path]) -> List[Finding]:
    """
    Perform read-only static analysis on a target repository path.

    Traverses Python, JavaScript, and TypeScript source files,
    ignoring standard build/environment directories, and returns
    all detected cryptographic findings.
    """
    root = Path(repo_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Target path does not exist: {repo_path}")

    findings: List[Finding] = []

    # If single file is provided
    if root.is_file():
        if root.suffix.lower() in PYTHON_EXTENSIONS:
            findings.extend(scan_python_file(root, repo_root=root.parent))
        elif root.suffix.lower() in JS_TS_EXTENSIONS:
            findings.extend(scan_js_ts_file(root, repo_root=root.parent))
        return findings

    # Traverse directory tree
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        # Modify dirnames in-place to prevent os.walk from descending into ignored dirs
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRECTORIES]

        current_dir = Path(dirpath)
        if should_ignore_path(current_dir):
            continue

        for filename in filenames:
            file_path = current_dir / filename
            ext = file_path.suffix.lower()

            if ext in PYTHON_EXTENSIONS:
                file_findings = scan_python_file(file_path, repo_root=root)
                findings.extend(file_findings)
            elif ext in JS_TS_EXTENSIONS:
                file_findings = scan_js_ts_file(file_path, repo_root=root)
                findings.extend(file_findings)

    return findings
