"""Data models for Qrypta Scanner."""

from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class Finding:
    """Represents a single cryptographic detection finding."""

    algorithm: str
    variant: Optional[str]
    primitive: str
    usage: str
    file: str
    line: int
    evidence: str
    library: Optional[str]
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to standard dictionary conforming to Qrypta schema."""
        return {
            "algorithm": self.algorithm,
            "variant": self.variant,
            "primitive": self.primitive,
            "usage": self.usage,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "library": self.library,
            "confidence": round(float(self.confidence), 2),
        }
