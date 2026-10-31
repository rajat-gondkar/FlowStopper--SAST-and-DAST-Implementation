"""Non-Python text files for the SAST scanners (Owner: A, P2-A4/A5).

The secrets detector (P2-A4) and the template scan (P2-A5) both walk the source tree for files the
Python index does not cover, and both read them as text - never parsed as Python, never imported,
compiled or executed (R7). Both policies live here so the two scanners cannot drift apart on
`SastConfig.exclude_dirs` or `SastConfig.max_text_file_bytes`.

Files are selected by **extension**, never by a basename that could encode a target app's layout
(R6); `extra_names` covers the few conventional extension-less file names a caller needs.
Discovery order is the relative POSIX path, so a scan is deterministic (FR-6).
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Optional

from FlowStopper.sast.config import SastConfig

log = logging.getLogger(__name__)


def text_files(
    root: Path,
    config: SastConfig,
    extensions: Iterable[str],
    extra_names: Iterable[str] = (),
) -> list[Path]:
    """Files under `root` selected by suffix, sorted by relative POSIX path.

    Directories named in `config.exclude_dirs` are pruned at any depth and symlinked directories
    are not followed. `extra_names` also matches a bare file name and `name.*`, for a conventional
    file that carries no extension of its own.
    """
    wanted = {ext.lower() for ext in extensions}
    names = tuple(extra_names)
    excluded = set(config.exclude_dirs)
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in excluded)
        for fname in sorted(filenames):
            if Path(fname).suffix.lower() in wanted or _named(fname, names):
                found.append(Path(dirpath) / fname)
    return sorted(found, key=lambda path: path.relative_to(root).as_posix())


def read_text(path: Path, rel: str, config: SastConfig, *, scanner: str) -> Optional[str]:
    """Text of one file, or None when it is larger than the cap or not decodable as UTF-8.

    `rel` and `scanner` only name the file and the caller in the warning log line.
    """
    try:
        if path.stat().st_size > config.max_text_file_bytes:
            log.warning("sast %s: skipping %s (larger than %d bytes)", scanner, rel, config.max_text_file_bytes)
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        log.warning("sast %s: skipping %s (%s)", scanner, rel, type(exc).__name__)
        return None


def _named(fname: str, names: tuple[str, ...]) -> bool:
    """True when `fname` is one of `names` or one of its suffixed variants (`Dockerfile.dev`)."""
    return any(fname == name or fname.startswith(f"{name}.") for name in names)
