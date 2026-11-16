"""Passive prompt-injection detection.

The scanner preserves the raw text and returns markers. It never rewrites or
obeys the content: taint isolation happens in the control plane, which has no
instruction channel from event fields.
"""

from __future__ import annotations

import re
from typing import Any

from evitrace.models import InjectionFlag

PATTERNS: tuple[tuple[str, str], ...] = (
    (
        r"ignore\s+(?:all\s+)?(?:prior|previous|above)\s+(?:rules|instructions)",
        "instruction_override",
    ),
    (r"disregard\s+(?:all\s+)?(?:prior|previous|above)", "instruction_override"),
    (r"mark\s+[a-z0-9_\- ]{1,40}\s+confirmed", "forced_verdict"),
    (r"state\s+no\s+malicious\s+activity", "forced_benign"),
    (r"you\s+are\s+now\s+(?:an?\s+)?(?:admin|system|developer)", "role_override"),
    (r"system\s*:\s*", "role_marker"),
)

COMPILED = tuple((re.compile(pattern, re.IGNORECASE), name) for pattern, name in PATTERNS)


def _walk(value: Any, prefix: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, str):
        found.append((prefix, value))
    elif isinstance(value, dict):
        for key, child in value.items():
            found.extend(_walk(child, f"{prefix}.{key}" if prefix else str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_walk(child, f"{prefix}[{index}]"))
    return found


def scan_record(event_id: str, record: dict[str, Any]) -> list[InjectionFlag]:
    """Return every injection marker found in a record, with its field path."""

    flags: list[InjectionFlag] = []
    seen: set[tuple[str, str]] = set()
    for field, text in _walk(record, ""):
        for regex, name in COMPILED:
            match = regex.search(text)
            if not match:
                continue
            key = (field, name)
            if key in seen:
                continue
            seen.add(key)
            if len(text) <= 180:
                excerpt = text
            else:
                start = max(0, match.start() - 30)
                if start:
                    boundary = text.find(" ", start, match.start())
                    start = boundary + 1 if boundary != -1 else start
                end = min(len(text), match.end() + 50)
                excerpt = text[start:end]
            excerpt = excerpt.replace("\n", " ").strip()
            flags.append(
                InjectionFlag(
                    event_id=event_id,
                    field=field or "record",
                    pattern=name,
                    excerpt=excerpt[:180],
                )
            )
    return flags
