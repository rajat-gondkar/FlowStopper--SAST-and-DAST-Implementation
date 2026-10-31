"""Answer-key schema (FlowStopper_BUILD_SPEC.md Appendix C). Part of contract-v1.

This is OUR format. The organisers do not prescribe one (their judges verify
findings by reading our output), so every key we use is written in this format:
fixtures/answer_key.json, apps/mock_a/answer_key.json, apps/mock_b/answer_key.json
and the git-ignored keys/answer_key.json for the organisers' app.
Human guide: docs/ANSWER_KEY_FORMAT.md.

Written in Phase 0 so keys can be authored and validated before evalkit exists;
owned by Dev B afterwards (additive changes only, logged in CONTRACT_CHANGES.md).

Validate a key:  python -m FlowStopper.evalkit.keyschema keys/answer_key.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class KeyCode(_Strict):
    file: str = Field(description="POSIX path relative to the scanned source root")
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    function: Optional[str] = Field(default=None, description="optional, informative only")

    @model_validator(mode="after")
    def _order(self) -> KeyCode:
        if self.line_end < self.line_start:
            raise ValueError("line_end must be >= line_start")
        if "\\" in self.file or self.file.startswith("/"):
            raise ValueError("file must be a relative POSIX path")
        return self


class KeyRuntime(_Strict):
    method: Optional[str] = Field(default=None, description="omit/null = any method")
    path: str = Field(description='path template; <...>/{...} are wildcards; "*" = host-wide')
    param: Optional[str] = Field(default=None, description="null = not parameter-specific")

    @field_validator("method")
    @classmethod
    def _upper(cls, v: Optional[str]) -> Optional[str]:
        return v.upper() if v else None

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        if v != "*" and not v.startswith("/"):
            raise ValueError('path must start with "/" or be "*"')
        return v


class KeyVuln(_Strict):
    id: str
    cwe: int
    kind: Literal["pair", "code_only", "runtime_only"]
    code: Optional[KeyCode] = None
    runtime: Optional[KeyRuntime] = None
    title: Optional[str] = None
    notes: Optional[str] = None

    @model_validator(mode="after")
    def _kind_matches_locations(self) -> KeyVuln:
        need_code = self.kind in ("pair", "code_only")
        need_runtime = self.kind in ("pair", "runtime_only")
        if need_code != (self.code is not None):
            raise ValueError(f"{self.id}: kind={self.kind} {'requires' if need_code else 'forbids'} 'code'")
        if need_runtime != (self.runtime is not None):
            raise ValueError(f"{self.id}: kind={self.kind} {'requires' if need_runtime else 'forbids'} 'runtime'")
        return self


class KeyDecoy(_Strict):
    id: str
    cwe: int
    file: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    reason: str


class AnswerKey(_Strict):
    schema_version: Literal["1"] = "1"
    app: str
    language: str = "python"
    framework: Optional[str] = None
    base_url: Optional[str] = Field(default=None, description="informative: where the app ran")
    vulns: list[KeyVuln]
    decoys: list[KeyDecoy] = []

    @model_validator(mode="after")
    def _unique_ids(self) -> AnswerKey:
        ids = [v.id for v in self.vulns] + [d.id for d in self.decoys]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"duplicate ids: {dupes}")
        return self

    def by_kind(self, kind: str) -> list[KeyVuln]:
        return [v for v in self.vulns if v.kind == kind]


def load_key(path: str | Path) -> AnswerKey:
    return AnswerKey.model_validate_json(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: python -m FlowStopper.evalkit.keyschema <key.json> [...]")
        return 1
    rc = 0
    for p in argv:
        try:
            key = load_key(p)
        except (OSError, ValidationError, json.JSONDecodeError) as exc:
            print(f"INVALID {p}\n{exc}")
            rc = 1
            continue
        counts = {k: len(key.by_kind(k)) for k in ("pair", "code_only", "runtime_only")}
        print(f"OK {p}: app={key.app} {counts} decoys={len(key.decoys)}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
