#!/usr/bin/env python3
"""Repository style and hygiene checker for blueprint-drift.

Enforces CONTRIBUTING.md rules:
- No em dashes (U+2014) or en dashes (U+2013)
- No emojis
- No accidental secrets or GitHub/AWS tokens
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

TEXT_EXTENSIONS = {
    ".md",
    ".yml",
    ".yaml",
    ".json",
    ".go",
    ".py",
    ".sh",
    ".txt",
    ".tmpl",
    ".html",
    ".csv",
    ".mod",
    "",
}

IGNORE_PREFIXES = (
    ".git/",
    "dist/",
    "bin/",
)

SECRET_PATTERNS = [
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "GitHub token pattern"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key pattern"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Private key block"),
]

# Files allowed to mention secret detection regexes themselves.
SECRET_CHECK_SKIP = {"scripts/style-check.py"}


def is_emoji(ch: str) -> bool:
    cp = ord(ch)
    return (
        0x1F300 <= cp <= 0x1FAFF
        or 0x2600 <= cp <= 0x27BF
        or 0x1F000 <= cp <= 0x1F02F
        or 0x1F0A0 <= cp <= 0x1F0FF
        or 0x1F100 <= cp <= 0x1F2FF
        or cp in (0xFE0F, 0x200D)
    )


def tracked_files() -> list[pathlib.Path]:
    result = subprocess.run(
        ["git", "ls-files"],
        check=True,
        capture_output=True,
        text=True,
    )
    paths: list[pathlib.Path] = []
    for line in result.stdout.splitlines():
        if not line or any(line.startswith(prefix) for prefix in IGNORE_PREFIXES):
            continue
        p = pathlib.Path(line)
        if p.is_file() and (p.suffix.lower() in TEXT_EXTENSIONS or p.name in {"Makefile", "Dockerfile", "LICENSE"}):
            paths.append(p)
    return paths


def main() -> int:
    errors: list[str] = []

    for path in tracked_files():
        rel = path.as_posix()
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        for lineno, line in enumerate(content.splitlines(), start=1):
            if "\u2014" in line:
                errors.append(f"{rel}:{lineno}: em dash (U+2014) is not permitted")
            if "\u2013" in line:
                errors.append(f"{rel}:{lineno}: en dash (U+2013) is not permitted")
            for ch in line:
                if is_emoji(ch):
                    errors.append(f"{rel}:{lineno}: emoji character U+{ord(ch):04X} is not permitted")
                    break

            if rel not in SECRET_CHECK_SKIP:
                for pattern, label in SECRET_PATTERNS:
                    if pattern.search(line):
                        errors.append(f"{rel}:{lineno}: possible secret detected ({label})")

    if errors:
        print("Style check failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(f"Style check passed across {len(tracked_files())} files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
