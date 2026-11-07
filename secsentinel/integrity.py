"""File integrity monitor.

``init`` records a SHA-256 baseline of a directory tree. ``check`` compares the
tree against that baseline and reports added, removed and modified files.
Symlinks are never followed.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

CHUNK_SIZE = 1024 * 1024
BASELINE_VERSION = 1


@dataclass
class Diff:
    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    modified: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not (self.added or self.removed or self.modified)


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _excluded(rel_path: str, patterns: Iterable[str]) -> bool:
    name = rel_path.rsplit("/", 1)[-1]
    return any(
        fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch(name, pat)
        for pat in patterns
    )


def scan(
    root: Path,
    excludes: Iterable[str] = (),
    skip: Iterable[Path] = (),
    errors: Optional[List[str]] = None,
) -> Dict[str, Dict[str, object]]:
    """Hash every regular file below ``root``. Returns ``{relative_path: info}``."""
    root = Path(root).resolve()
    excludes = list(excludes)
    skip_set = {Path(p).resolve() for p in skip}
    result: Dict[str, Dict[str, object]] = {}

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        dirnames[:] = sorted(
            d
            for d in dirnames
            if not _excluded((base / d).relative_to(root).as_posix(), excludes)
        )
        for name in sorted(filenames):
            path = base / name
            rel = path.relative_to(root).as_posix()
            if _excluded(rel, excludes) or path.resolve() in skip_set:
                continue
            if path.is_symlink() or not path.is_file():
                continue
            try:
                result[rel] = {
                    "sha256": hash_file(path),
                    "size": path.stat().st_size,
                }
            except OSError as exc:
                if errors is not None:
                    errors.append(f"{rel}: {exc.strerror or exc}")
    return result


def save_baseline(
    root: Path, baseline_path: Path, excludes: Iterable[str] = ()
) -> int:
    """Create a baseline file and return the number of files recorded."""
    root = Path(root).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")
    excludes = list(excludes)
    files = scan(root, excludes, skip=[baseline_path])
    payload = {
        "version": BASELINE_VERSION,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "root": str(root),
        "excludes": excludes,
        "files": files,
    }
    Path(baseline_path).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return len(files)


def load_baseline(baseline_path: Path) -> dict:
    data = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    if data.get("version") != BASELINE_VERSION or "files" not in data:
        raise ValueError("unsupported or corrupt baseline file")
    return data


def compare(baseline: Dict[str, Dict[str, object]], current: Dict[str, Dict[str, object]]) -> Diff:
    old, new = set(baseline), set(current)
    return Diff(
        added=sorted(new - old),
        removed=sorted(old - new),
        modified=sorted(
            p for p in old & new if baseline[p]["sha256"] != current[p]["sha256"]
        ),
    )


def check(root: Path, baseline_path: Path, extra_excludes: Iterable[str] = ()) -> Diff:
    """Compare ``root`` to the stored baseline."""
    data = load_baseline(baseline_path)
    excludes = list(data.get("excludes", [])) + list(extra_excludes)
    errors: List[str] = []
    current = scan(root, excludes, skip=[baseline_path], errors=errors)
    diff = compare(data["files"], current)
    diff.errors = errors
    return diff


def format_diff(diff: Diff) -> str:
    lines = ["SecSentinel - integrity report"]
    if diff.clean:
        lines.append("OK: no changes since baseline.")
    for label, items in (
        ("MODIFIED", diff.modified),
        ("ADDED   ", diff.added),
        ("REMOVED ", diff.removed),
    ):
        for item in items:
            lines.append(f"[{label}] {item}")
    for err in diff.errors:
        lines.append(f"[ERROR   ] {err}")
    return "\n".join(lines)
