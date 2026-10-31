"""Export JSON Schemas for the shared contracts to docs/schemas/ (P0-J2).

python scripts/export_schemas.py          # rewrite docs/schemas/*.schema.json
python scripts/export_schemas.py --check  # exit 1 if stale (used by tests)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from FlowStopper.evalkit.keyschema import AnswerKey  # noqa: E402
from FlowStopper.models import DastResult, Finding, Issue, Route, SastResult  # noqa: E402

OUT = ROOT / "docs" / "schemas"
MODELS = {
    "finding": Finding,
    "route": Route,
    "issue": Issue,
    "sast_result": SastResult,
    "dast_result": DastResult,
    "answer_key": AnswerKey,
}


def render() -> dict[str, str]:
    return {f"{name}.schema.json": json.dumps(m.model_json_schema(), indent=2) + "\n" for name, m in MODELS.items()}


def stale_files() -> list[str]:
    return [n for n, t in render().items() if not (OUT / n).exists() or (OUT / n).read_text(encoding="utf-8") != t]


def main(argv: list[str]) -> int:
    if "--check" in argv:
        stale = stale_files()
        if stale:
            print(f"stale schemas: {stale}; run: python scripts/export_schemas.py")
            return 1
        print("schemas up to date")
        return 0
    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in render().items():
        (OUT / name).write_text(text, encoding="utf-8")
        print(f"wrote docs/schemas/{name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
