#!/usr/bin/env python3
"""PreToolUse guard: forbid the AI agent from running `git add`, `git commit`, `git push`.

Wired by .kiro/hooks/block-git-writes.json, which runs this on every bash-style tool call and passes
the tool's JSON on stdin. We scan every shell command string in that payload and exit 2 (block) if any
invokes one of those three git subcommands. All other git commands (status, diff, log, clone, checkout,
merge, rev-parse, check-ignore, tag, ...) are allowed.

Person 1 (a human) stages, commits and pushes manually — see docs/SETUP.md and docs/DECISIONS.md D-17.
Fails open (exit 0) only if stdin is unreadable, so a malformed payload never silently wedges tooling.
"""

from __future__ import annotations

import json
import re
import sys

# `git` at a command position (start of a segment, or after a separator like && ; | newline ( `),
# optional global flags (incl. `-C <path>` / `-c <cfg>`), then add|commit|push as the subcommand.
# The command-position anchor keeps quoted mentions (e.g. grep "git push") from being blocked.
BLOCKED = re.compile(
    r"(?:^|[\n;&|(`])\s*git\b(?:\s+(?:-C\s+\S+|-c\s+\S+|--[^\s=]+=\S+|--[^\s]+|-\w))*\s+(add|commit|push)\b"
)


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def main() -> int:
    raw = sys.stdin.read()
    try:
        blob = "\n".join(_strings(json.loads(raw)))
    except Exception:
        blob = raw
    m = BLOCKED.search(blob)
    if m:
        sub = m.group(1)
        sys.stderr.write(
            f"BLOCKED by the block-git-writes hook: `git {sub}` is disabled for the AI agent in this "
            "repository. Person 1 stages, commits and pushes manually (docs/SETUP.md). Make the file "
            "changes only and leave `git add` / `git commit` / `git push` to a human."
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
