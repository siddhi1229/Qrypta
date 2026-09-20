"""Simple, zero-dependency HTTP server for Qrypta frontend and scan/approval API."""

import json
import os
import sys
import tempfile
import uuid
from http.server import SimpleHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Dict, Any, Optional

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).parent.resolve()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from qrypta.pipeline import run_pipeline
from qrypta.approval import (
    create_approval_request,
    approve_migration,
    reject_migration,
    STATUS_AWAITING_APPROVAL,
    STATUS_APPROVED,
    STATUS_REJECTED,
)
from qrypta.patch.generator import generate_patches
from qrypta.validate.validator import validate_patches

# In-memory session state for the active scan run
ACTIVE_RUN: Dict[str, Any] = {}


class QryptaHTTPRequestHandler(SimpleHTTPRequestHandler):
    """Custom HTTP request handler serving static frontend and Qrypta API endpoints."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PROJECT_ROOT), **kwargs)

    def do_GET(self):
        """Handle GET requests for static files and migration review."""
        if self.path.startswith("/api/migration/review"):
            approval_req = ACTIVE_RUN.get("approval_request")
            if approval_req:
                self._send_json_response(200, {"success": True, "data": approval_req})
            else:
                self._send_json_response(200, {
                    "success": True,
                    "data": {
                        "status": "NO_ACTIVE_RUN",
                        "summary": {
                            "proposed_changes": 0,
                            "automatic_patches": 0,
                            "manual_review_items": 0,
                            "no_change_findings": 0,
                            "affected_files": 0,
                            "validation_status": "UNKNOWN",
                        },
                        "review_items": [],
                        "diffs": [],
                        "original_repository_modified": False,
                        "original_repository_status": "ORIGINAL REPOSITORY: UNMODIFIED",
                    }
                })
        else:
            super().do_GET()

    def do_POST(self):
        """Handle POST requests for scan, approve, and reject."""
        if self.path == "/api/scan":
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                post_data = self.rfile.read(content_length)
                req_json = json.loads(post_data.decode("utf-8"))

                # Create persistent sandbox for this active run
                sandbox_dir_obj = tempfile.TemporaryDirectory()
                sandbox_path = Path(sandbox_dir_obj.name).resolve()
                temp_source_dir_obj = None

                # Case 1: Files uploaded as JSON array of {path, content}
                if "files" in req_json and isinstance(req_json["files"], list):
                    temp_source_dir_obj = tempfile.TemporaryDirectory()
                    target_path = Path(temp_source_dir_obj.name).resolve()
                    for file_obj in req_json["files"]:
                        rel_path_str = file_obj.get("path", "")
                        content_str = file_obj.get("content", "")

                        parts = Path(rel_path_str).parts
                        if len(parts) > 1:
                            dest_rel = Path(*parts[1:])
                        elif len(parts) == 1:
                            dest_rel = Path(parts[0])
                        else:
                            continue

                        dest_file = (target_path / dest_rel).resolve()
                        if not dest_file.is_relative_to(target_path):
                            continue

                        dest_file.parent.mkdir(parents=True, exist_ok=True)
                        dest_file.write_text(content_str, encoding="utf-8", errors="replace")

                # Case 2: Repository path provided directly
                elif "repository_path" in req_json:
                    target_path = Path(req_json["repository_path"]).resolve()
                    if not target_path.exists():
                        target_path = (PROJECT_ROOT / req_json["repository_path"]).resolve()
                else:
                    self._send_json_response(400, {"error": "Invalid request: provide 'files' or 'repository_path'"})
                    return

                # Run complete analysis pipeline with dedicated sandbox
                result = run_pipeline(target_path)
                patch_result = generate_patches(target_path, result.get("migration", []), sandbox_path=sandbox_path)
                validation_result = validate_patches(target_path, patch_result)
                result["patch"] = patch_result
                result["validation"] = validation_result

                # Synthesize Human Approval Request
                approval_req = create_approval_request(
                    pipeline_result=result,
                    repository_path=target_path,
                    sandbox_path=sandbox_path,
                )
                result["approval"] = approval_req

                # Update in-memory active run
                ACTIVE_RUN.clear()
                ACTIVE_RUN["run_id"] = str(uuid.uuid4())
                ACTIVE_RUN["repo_path"] = target_path
                ACTIVE_RUN["sandbox_path"] = sandbox_path
                ACTIVE_RUN["sandbox_dir_obj"] = sandbox_dir_obj
                ACTIVE_RUN["temp_source_dir_obj"] = temp_source_dir_obj
                ACTIVE_RUN["pipeline_result"] = result
                ACTIVE_RUN["approval_request"] = approval_req

                # Ensure finding objects are converted to dicts for JSON serialization
                result["findings"] = [
                    f.to_dict() if hasattr(f, "to_dict") else f for f in result.get("findings", [])
                ]

                self._send_json_response(200, {"success": True, "data": result})

            except Exception as e:
                self._send_json_response(500, {"error": str(e)})

        elif self.path == "/api/migration/approve":
            try:
                approval_req = ACTIVE_RUN.get("approval_request")
                repo_path = ACTIVE_RUN.get("repo_path")
                sb_path = ACTIVE_RUN.get("sandbox_path")

                if not approval_req:
                    self._send_json_response(400, {"error": "No active migration run to approve. Please scan a repository first."})
                    return

                approve_data = approve_migration(
                    approval_request=approval_req,
                    repository_path=repo_path,
                    sandbox_path=sb_path,
                )
                self._send_json_response(200, {"success": True, "data": approve_data})

            except Exception as e:
                self._send_json_response(500, {"error": str(e)})

        elif self.path == "/api/migration/reject":
            try:
                approval_req = ACTIVE_RUN.get("approval_request")
                if not approval_req:
                    self._send_json_response(400, {"error": "No active migration run to reject."})
                    return

                reject_data = reject_migration(approval_request=approval_req)
                self._send_json_response(200, {"success": True, "data": reject_data})

            except Exception as e:
                self._send_json_response(500, {"error": str(e)})

        else:
            self.send_error(404, "Endpoint not found")

    def _send_json_response(self, status_code: int, data: dict):
        """Send JSON response with appropriate headers."""
        response_bytes = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(response_bytes)

    def do_OPTIONS(self):
        """Handle CORS pre-flight requests."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


def run_server(port: int = 8000):
    """Start Qrypta server."""
    server_address = ("", port)
    httpd = HTTPServer(server_address, QryptaHTTPRequestHandler)
    print(f"QRYPTA Server running on http://localhost:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        httpd.server_close()


if __name__ == "__main__":
    port = 8000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port)
