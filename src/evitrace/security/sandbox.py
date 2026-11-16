"""Path and file-size validation for every untrusted input."""

from __future__ import annotations

import hashlib
from pathlib import Path

MAX_ARTIFACT_BYTES = 250 * 1024 * 1024
MAX_LINE_CHARS = 1_000_000
DEFAULT_ROOTS = (Path.cwd(),)


class SandboxError(ValueError):
    """Raised when an input path or file violates the evidence sandbox."""


def safe_resolve_path(path: str | Path, roots: tuple[Path, ...] | None = None) -> Path:
    """Resolve a path and require it to live under one of the allowed roots."""

    allowed = tuple(root.resolve() for root in (roots or DEFAULT_ROOTS))
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = allowed[0] / candidate
    resolved = candidate.resolve()
    if not any(resolved.is_relative_to(root) for root in allowed):
        raise SandboxError(f"path escapes the allowed roots: {resolved}")
    if not resolved.exists() or not resolved.is_file():
        raise SandboxError(f"artifact is not a readable file: {resolved}")
    size = resolved.stat().st_size
    if size > MAX_ARTIFACT_BYTES:
        raise SandboxError(f"artifact exceeds {MAX_ARTIFACT_BYTES} bytes: {size}")
    return resolved


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_line_length(line: str, *, source: str = "") -> None:
    if len(line) > MAX_LINE_CHARS:
        raise SandboxError(f"line exceeds {MAX_LINE_CHARS} characters in {source or 'input'}")
