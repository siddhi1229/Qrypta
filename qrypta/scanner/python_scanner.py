"""Python static analysis scanner using Python AST and fallback regex scanning."""

import ast
import re
from pathlib import Path
from typing import List, Optional, Set, Dict, Tuple, Any

from qrypta.scanner.models import Finding
from qrypta.scanner.rules import (
    ALGORITHM_RULES,
    NAME_TO_RULE_KEY,
    PRIMITIVE_ASYMMETRIC_ENCRYPTION,
    PRIMITIVE_ASYMMETRIC_SIGNATURE,
    PRIMITIVE_ASYMMETRIC_KEY_EXCHANGE,
    PRIMITIVE_SYMMETRIC_ENCRYPTION,
    PRIMITIVE_HASH_FUNCTION,
    PRIMITIVE_JWT_SIGNATURE,
    PRIMITIVE_PROTOCOL,
)

# Known libraries and their common module prefixes
KNOWN_LIBRARIES = {
    "hashlib": "hashlib",
    "ssl": "ssl",
    "jwt": "PyJWT",
    "jose": "python-jose",
    "cryptography": "cryptography",
    "Crypto": "pycryptodome",
    "Cryptodome": "pycryptodome",
    "nacl": "PyNaCl",
    "ecdsa": "ecdsa",
    "pyDes": "pyDes",
}

# Regex for string/constant lookup fallback
HASH_ATTRS = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}
CIPHER_ATTRS = {"aes": "AES", "chacha20": "ChaCha20", "des": "DES", "des3": "3DES", "tripledes": "3DES"}
ASYM_ATTRS = {
    "rsa": "RSA",
    "ec": "ECDSA",
    "ecdsa": "ECDSA",
    "ecdh": "ECDH",
    "ed25519": "Ed25519",
    "eddsa": "EdDSA",
    "dh": "Diffie-Hellman",
}


class PythonASTVisitor(ast.NodeVisitor):
    """AST Visitor that traverses Python code to detect cryptographic usages."""

    def __init__(self, filename: str, source_lines: List[str]):
        self.filename = filename
        self.source_lines = source_lines
        self.findings: List[Finding] = []
        self.imported_modules: Dict[str, str] = {}  # alias -> original_module
        self.imported_symbols: Dict[str, Tuple[str, str]] = {}  # alias -> (module, symbol)
        self.reported_lines: Set[Tuple[int, str]] = set()  # (line, algorithm) to avoid duplicate hits on same line

    def _get_line_evidence(self, lineno: int) -> str:
        """Extract stripped source line as evidence."""
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _add_finding(
        self,
        algorithm: str,
        variant: Optional[str],
        primitive: str,
        usage: str,
        line: int,
        library: Optional[str],
        confidence: float,
    ) -> None:
        """Record finding if not already reported for this line and algorithm."""
        dedup_key = (line, algorithm)
        if dedup_key in self.reported_lines:
            return
        self.reported_lines.add(dedup_key)

        evidence = self._get_line_evidence(line)
        self.findings.append(
            Finding(
                algorithm=algorithm,
                variant=variant,
                primitive=primitive,
                usage=usage,
                file=self.filename,
                line=line,
                evidence=evidence,
                library=library,
                confidence=confidence,
            )
        )

    def visit_Import(self, node: ast.Import) -> None:
        """Track direct imports."""
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name
            self.imported_modules[asname] = name

            # Detect direct library imports
            base = name.split(".")[0]
            if base in KNOWN_LIBRARIES:
                lib_name = KNOWN_LIBRARIES[base]
                # If specific algorithm module is imported (e.g. import hashlib)
                # We do not immediately flag 'import hashlib' as finding to avoid noise,
                # but we track the context.
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track 'from module import symbol' imports."""
        module = node.module or ""
        base_mod = module.split(".")[0]
        lib_name = KNOWN_LIBRARIES.get(base_mod, base_mod)

        for alias in node.names:
            sym = alias.name
            asname = alias.asname or sym
            self.imported_symbols[asname] = (module, sym)

            # Check if specific algorithm symbol is imported (e.g. from Crypto.Cipher import AES)
            lower_sym = sym.lower()
            if lower_sym in NAME_TO_RULE_KEY and base_mod in {"Crypto", "Cryptodome", "cryptography", "nacl", "ecdsa"}:
                rule_key = NAME_TO_RULE_KEY[lower_sym]
                rule = ALGORITHM_RULES.get(rule_key)
                if rule:
                    self._add_finding(
                        algorithm=rule["algorithm"],
                        variant=rule.get("variant"),
                        primitive=rule["primitive"],
                        usage="import",
                        line=node.lineno,
                        library=lib_name,
                        confidence=0.85,
                    )

        self.generic_visit(node)

    def _resolve_call_name(self, node: ast.AST) -> Tuple[str, Optional[str]]:
        """Resolve call node to (full_call_string, base_library)."""
        parts = []
        curr = node
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
        parts.reverse()

        call_str = ".".join(parts)
        if not parts:
            return "", None

        first_part = parts[0]
        lib = None

        if first_part in self.imported_modules:
            orig = self.imported_modules[first_part]
            base = orig.split(".")[0]
            lib = KNOWN_LIBRARIES.get(base, base)
        elif first_part in self.imported_symbols:
            mod, _ = self.imported_symbols[first_part]
            base = mod.split(".")[0]
            lib = KNOWN_LIBRARIES.get(base, base)
        elif first_part in KNOWN_LIBRARIES:
            lib = KNOWN_LIBRARIES[first_part]

        return call_str, lib

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect function and method calls."""
        call_str, lib = self._resolve_call_name(node.func)
        lower_call = call_str.lower()
        lineno = node.lineno

        # 1. hashlib detections (e.g., hashlib.sha256(), hashlib.md5(), hashlib.new('sha256'))
        if "hashlib" in lower_call or lib == "hashlib":
            if "new" in lower_call and node.args:
                # hashlib.new('algorithm')
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                    algo_str = first_arg.value.lower()
                    if algo_str in NAME_TO_RULE_KEY:
                        rule = ALGORITHM_RULES[NAME_TO_RULE_KEY[algo_str]]
                        self._add_finding(
                            algorithm=rule["algorithm"],
                            variant=rule.get("variant"),
                            primitive=rule["primitive"],
                            usage="hashing",
                            line=lineno,
                            library="hashlib",
                            confidence=0.95,
                        )
            else:
                for func_name, algo_name in HASH_ATTRS.items():
                    if lower_call.endswith("." + func_name) or lower_call == func_name:
                        rule = ALGORITHM_RULES[algo_name]
                        self._add_finding(
                            algorithm=rule["algorithm"],
                            variant=rule.get("variant"),
                            primitive=rule["primitive"],
                            usage="hashing",
                            line=lineno,
                            library="hashlib",
                            confidence=0.95,
                        )

        # 2. PyJWT / jwt.encode / jwt.decode
        if "jwt." in lower_call or lib in {"PyJWT", "jwt", "python-jose"}:
            algo_found = None
            # Check keywords for algorithm or algorithms
            for kw in node.keywords:
                if kw.arg == "algorithm":
                    if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        algo_found = kw.value.value
                elif kw.arg == "algorithms":
                    if isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                        for elt in kw.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                algo_val = elt.value.upper()
                                if algo_val in ALGORITHM_RULES:
                                    rule = ALGORITHM_RULES[algo_val]
                                    self._add_finding(
                                        algorithm=rule["algorithm"],
                                        variant=rule.get("variant"),
                                        primitive=rule["primitive"],
                                        usage="token_verification" if "decode" in lower_call else "token_signing",
                                        line=lineno,
                                        library=lib or "PyJWT",
                                        confidence=0.95,
                                    )
            if algo_found:
                algo_upper = algo_found.upper()
                if algo_upper in ALGORITHM_RULES:
                    rule = ALGORITHM_RULES[algo_upper]
                    self._add_finding(
                        algorithm=rule["algorithm"],
                        variant=rule.get("variant"),
                        primitive=rule["primitive"],
                        usage="token_signing" if "encode" in lower_call else "token_verification",
                        line=lineno,
                        library=lib or "PyJWT",
                        confidence=0.95,
                    )

        # 3. cryptography library detections
        # RSA key generation
        if "rsa.generate_private_key" in lower_call or lower_call == "generate_private_key":
            # Extract key size if present
            variant = None
            for kw in node.keywords:
                if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                    variant = f"{kw.value.value}-bit"
            if not variant and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                variant = f"{node.args[1].value}-bit"
            self._add_finding(
                algorithm="RSA",
                variant=variant,
                primitive=PRIMITIVE_ASYMMETRIC_ENCRYPTION,
                usage="key_generation",
                line=lineno,
                library=lib or "cryptography",
                confidence=0.95,
            )

        # EC / ECDSA / ECDH key generation
        if "ec.generate_private_key" in lower_call:
            curve_name = None
            if node.args:
                curve_node = node.args[0]
                if isinstance(curve_node, ast.Call):
                    call_name, _ = self._resolve_call_name(curve_node.func)
                    curve_name = call_name.split(".")[-1]
                elif isinstance(curve_node, ast.Attribute):
                    curve_name = curve_node.attr
            self._add_finding(
                algorithm="ECDSA",
                variant=curve_name,
                primitive=PRIMITIVE_ASYMMETRIC_SIGNATURE,
                usage="key_generation",
                line=lineno,
                library=lib or "cryptography",
                confidence=0.95,
            )

        # Ed25519 key generation
        if "ed25519" in lower_call and "generate" in lower_call:
            self._add_finding(
                algorithm="Ed25519",
                variant=None,
                primitive=PRIMITIVE_ASYMMETRIC_SIGNATURE,
                usage="key_generation",
                line=lineno,
                library=lib or "cryptography",
                confidence=0.95,
            )

        # Diffie-Hellman parameters / key generation
        if "dh.generate_parameters" in lower_call or ("dh" in lower_call and "generate" in lower_call):
            variant = None
            for kw in node.keywords:
                if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                    variant = f"{kw.value.value}-bit"
            self._add_finding(
                algorithm="Diffie-Hellman",
                variant=variant,
                primitive=PRIMITIVE_ASYMMETRIC_KEY_EXCHANGE,
                usage="key_generation",
                line=lineno,
                library=lib or "cryptography",
                confidence=0.95,
            )

        # Cipher / algorithms.AES / ChaCha20 / TripleDES
        if "algorithms.aes" in lower_call or lower_call.endswith(".aes") and lib in {"cryptography", "pycryptodome"}:
            self._add_finding(
                algorithm="AES",
                variant=None,
                primitive=PRIMITIVE_SYMMETRIC_ENCRYPTION,
                usage="encryption",
                line=lineno,
                library=lib or "cryptography",
                confidence=0.95,
            )
        elif "algorithms.chacha20" in lower_call or (
            "chacha20" in lower_call and lib in {"cryptography", "pycryptodome"}
        ):
            self._add_finding(
                algorithm="ChaCha20",
                variant=None,
                primitive=PRIMITIVE_SYMMETRIC_ENCRYPTION,
                usage="encryption",
                line=lineno,
                library=lib or "cryptography",
                confidence=0.95,
            )
        elif (
            "algorithms.tripledes" in lower_call
            or "tripledes" in lower_call
            or ("des3" in lower_call and lib in {"cryptography", "pycryptodome"})
        ):
            self._add_finding(
                algorithm="3DES",
                variant=None,
                primitive=PRIMITIVE_SYMMETRIC_ENCRYPTION,
                usage="encryption",
                line=lineno,
                library=lib or "cryptography",
                confidence=0.95,
            )
        elif (
            "algorithms.des" in lower_call
            or lower_call == "des.new"
            or (lower_call.endswith(".des") and lib in {"pycryptodome", "pyDes"})
        ):
            self._add_finding(
                algorithm="DES",
                variant=None,
                primitive=PRIMITIVE_SYMMETRIC_ENCRYPTION,
                usage="encryption",
                line=lineno,
                library=lib or "pycryptodome",
                confidence=0.95,
            )

        # 4. PyCryptodome / Crypto.Cipher / Crypto.PublicKey calls
        if "aes.new" in lower_call:
            self._add_finding(
                algorithm="AES",
                variant=None,
                primitive=PRIMITIVE_SYMMETRIC_ENCRYPTION,
                usage="encryption",
                line=lineno,
                library="pycryptodome",
                confidence=0.95,
            )
        elif "rsa.generate" in lower_call:
            variant = None
            if node.args and isinstance(node.args[0], ast.Constant):
                variant = f"{node.args[0].value}-bit"
            self._add_finding(
                algorithm="RSA",
                variant=variant,
                primitive=PRIMITIVE_ASYMMETRIC_ENCRYPTION,
                usage="key_generation",
                line=lineno,
                library=lib or "pycryptodome",
                confidence=0.95,
            )
        elif "ecc.generate" in lower_call:
            variant = None
            for kw in node.keywords:
                if kw.arg == "curve" and isinstance(kw.value, ast.Constant):
                    variant = str(kw.value.value)
            self._add_finding(
                algorithm="ECDSA",
                variant=variant,
                primitive=PRIMITIVE_ASYMMETRIC_SIGNATURE,
                usage="key_generation",
                line=lineno,
                library=lib or "pycryptodome",
                confidence=0.95,
            )

        # 5. SSL / TLS usage (create_default_context, SSLContext, etc.)
        if "ssl.create_default_context" in lower_call or "create_default_context" in lower_call:
            self._add_finding(
                algorithm="TLS",
                variant=None,
                primitive=PRIMITIVE_PROTOCOL,
                usage="secure_channel",
                line=lineno,
                library="ssl",
                confidence=0.95,
            )
        elif "sslcontext" in lower_call or "ssl.sslcontext" in lower_call:
            self._add_finding(
                algorithm="TLS/SSL",
                variant=None,
                primitive=PRIMITIVE_PROTOCOL,
                usage="secure_channel",
                line=lineno,
                library="ssl",
                confidence=0.95,
            )

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Inspect attributes for constants like ssl.PROTOCOL_TLSv1_2 or hashes.SHA256."""
        attr_name = node.attr
        lineno = node.lineno

        # Check for SSL protocol attributes
        if attr_name.startswith("PROTOCOL_") or attr_name.startswith("TLSv1"):
            if "TLSv1_3" in attr_name:
                self._add_finding(
                    algorithm="TLS",
                    variant="TLS 1.3",
                    primitive=PRIMITIVE_PROTOCOL,
                    usage="protocol_configuration",
                    line=lineno,
                    library="ssl",
                    confidence=0.95,
                )
            elif "TLSv1_2" in attr_name:
                self._add_finding(
                    algorithm="TLS",
                    variant="TLS 1.2",
                    primitive=PRIMITIVE_PROTOCOL,
                    usage="protocol_configuration",
                    line=lineno,
                    library="ssl",
                    confidence=0.95,
                )
            elif "TLSv1_1" in attr_name:
                self._add_finding(
                    algorithm="TLS",
                    variant="TLS 1.1",
                    primitive=PRIMITIVE_PROTOCOL,
                    usage="protocol_configuration",
                    line=lineno,
                    library="ssl",
                    confidence=0.95,
                )
            elif "TLSv1" in attr_name:
                self._add_finding(
                    algorithm="TLS",
                    variant="TLS 1.0",
                    primitive=PRIMITIVE_PROTOCOL,
                    usage="protocol_configuration",
                    line=lineno,
                    library="ssl",
                    confidence=0.95,
                )
            elif "SSLv2" in attr_name:
                self._add_finding(
                    algorithm="SSL",
                    variant="SSLv2",
                    primitive=PRIMITIVE_PROTOCOL,
                    usage="protocol_configuration",
                    line=lineno,
                    library="ssl",
                    confidence=0.95,
                )
            elif "SSLv3" in attr_name:
                self._add_finding(
                    algorithm="SSL",
                    variant="SSLv3",
                    primitive=PRIMITIVE_PROTOCOL,
                    usage="protocol_configuration",
                    line=lineno,
                    library="ssl",
                    confidence=0.95,
                )
            elif "PROTOCOL_TLS" in attr_name:
                self._add_finding(
                    algorithm="TLS",
                    variant=None,
                    primitive=PRIMITIVE_PROTOCOL,
                    usage="protocol_configuration",
                    line=lineno,
                    library="ssl",
                    confidence=0.95,
                )

        # Check for cryptography hashes (hashes.SHA256, hashes.MD5, etc.)
        if isinstance(node.value, ast.Name) and node.value.id == "hashes":
            upper_attr = attr_name.upper()
            if upper_attr in {"SHA256", "SHA384", "SHA512", "SHA1", "MD5"}:
                rule_key = NAME_TO_RULE_KEY.get(upper_attr.lower(), upper_attr)
                rule = ALGORITHM_RULES.get(rule_key)
                if rule:
                    self._add_finding(
                        algorithm=rule["algorithm"],
                        variant=rule.get("variant"),
                        primitive=rule["primitive"],
                        usage="hashing",
                        line=lineno,
                        library="cryptography",
                        confidence=0.95,
                    )

        self.generic_visit(node)


def scan_python_regex_fallback(filename: str, source_text: str) -> List[Finding]:
    """Fallback scanner for Python files using deterministic regex when AST fails."""
    findings: List[Finding] = []
    lines = source_text.splitlines()

    # Common regex patterns
    patterns = [
        (r"\bhashlib\.(sha256|sha384|sha512|sha1|md5)\b", "hashlib", PRIMITIVE_HASH_FUNCTION, "hashing"),
        (r"\bhashlib\.new\s*\(\s*['\"](sha256|sha384|sha512|sha1|md5)['\"]", "hashlib", PRIMITIVE_HASH_FUNCTION, "hashing"),
        (r"\b(?:AES|DES|DES3|ChaCha20)\.new\b", "pycryptodome", PRIMITIVE_SYMMETRIC_ENCRYPTION, "encryption"),
        (r"\b(RS256|RS384|RS512|ES256|ES384|ES512|HS256|HS384|HS512)\b", "jwt", PRIMITIVE_JWT_SIGNATURE, "token_signing"),
        (r"(?:PROTOCOL_|TLSVersion\.)?(TLSv1_3|TLSv1_2|TLSv1_1|TLSv1|SSLv3|SSLv2|PROTOCOL_TLS_CLIENT|PROTOCOL_TLS_SERVER|PROTOCOL_TLS)", "ssl", PRIMITIVE_PROTOCOL, "protocol_configuration"),
        (r"\brsa\.generate_private_key\b", "cryptography", PRIMITIVE_ASYMMETRIC_ENCRYPTION, "key_generation"),
        (r"\bec\.generate_private_key\b", "cryptography", PRIMITIVE_ASYMMETRIC_SIGNATURE, "key_generation"),
        (r"\bed25519\.Ed25519PrivateKey\.generate\b", "cryptography", PRIMITIVE_ASYMMETRIC_SIGNATURE, "key_generation"),
        (r"\bdh\.generate_parameters\b", "cryptography", PRIMITIVE_ASYMMETRIC_KEY_EXCHANGE, "key_generation"),
    ]

    for line_idx, line in enumerate(lines, 1):
        clean_line = line.strip()
        if clean_line.startswith("#"):
            continue

        for regex, lib, prim, usage in patterns:
            match = re.search(regex, line, re.IGNORECASE)
            if match:
                matched_group = match.group(1) if match.groups() else match.group(0)
                matched_lower = matched_group.lower()

                algo = matched_group.upper()
                variant = None
                primitive = prim

                if "tlsv1_3" in matched_lower or "tlsv1.3" in matched_lower:
                    algo = "TLS"
                    variant = "TLS 1.3"
                elif "tlsv1_2" in matched_lower or "tlsv1.2" in matched_lower:
                    algo = "TLS"
                    variant = "TLS 1.2"
                elif "tlsv1_1" in matched_lower or "tlsv1.1" in matched_lower:
                    algo = "TLS"
                    variant = "TLS 1.1"
                elif "tlsv1" in matched_lower:
                    algo = "TLS"
                    variant = "TLS 1.0"
                elif "sslv3" in matched_lower:
                    algo = "SSL"
                    variant = "SSLv3"
                elif "sslv2" in matched_lower:
                    algo = "SSL"
                    variant = "SSLv2"
                elif "protocol_tls" in matched_lower:
                    algo = "TLS"
                    variant = None
                elif matched_lower in NAME_TO_RULE_KEY:
                    rule_key = NAME_TO_RULE_KEY[matched_lower]
                    target_rule = ALGORITHM_RULES[rule_key]
                    algo = target_rule["algorithm"]
                    variant = target_rule.get("variant")
                    primitive = target_rule["primitive"]

                findings.append(
                    Finding(
                        algorithm=algo,
                        variant=variant,
                        primitive=primitive,
                        usage=usage,
                        file=filename,
                        line=line_idx,
                        evidence=clean_line,
                        library=lib,
                        confidence=0.75,
                    )
                )

    return findings


def scan_python_code(source_code: str, filename: str = "source.py") -> List[Finding]:
    """Scan Python source code string and return cryptographic findings."""
    source_lines = source_code.splitlines()
    try:
        tree = ast.parse(source_code, filename=filename)
        visitor = PythonASTVisitor(filename=filename, source_lines=source_lines)
        visitor.visit(tree)
        return visitor.findings
    except SyntaxError:
        return scan_python_regex_fallback(filename=filename, source_text=source_code)


def scan_python_file(file_path: Path, repo_root: Optional[Path] = None) -> List[Finding]:
    """Read and scan a Python file from disk in read-only mode."""
    rel_path = file_path.relative_to(repo_root).as_posix() if repo_root else file_path.as_posix()
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return scan_python_code(content, filename=rel_path)
    except Exception:
        return []
