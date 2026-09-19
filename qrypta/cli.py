"""CLI entry point for Qrypta Static Analysis Scanner."""

import argparse
import json
import sys
from pathlib import Path

from qrypta.scanner.engine import scan_repository


def main() -> None:
    """Run CLI scanner interface."""
    parser = argparse.ArgumentParser(
        description="Qrypta Static Analysis Scanner - Detect cryptographic usage in source code."
    )
    parser.add_argument(
        "repository_path",
        type=str,
        help="Path to the repository or directory to scan.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Optional file path to save findings JSON.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output with indentation.",
    )

    args = parser.parse_args()

    repo_path = Path(args.repository_path)
    if not repo_path.exists():
        sys.stderr.write(f"Error: Path '{args.repository_path}' does not exist.\n")
        sys.exit(1)

    try:
        findings = scan_repository(repo_path)
        findings_data = [f.to_dict() for f in findings]
        indent = 2 if args.pretty else None
        json_output = json.dumps(findings_data, indent=indent)

        if args.output:
            output_file = Path(args.output)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(json_output + "\n")
        else:
            print(json_output)

    except Exception as exc:
        sys.stderr.write(f"Scan error: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
