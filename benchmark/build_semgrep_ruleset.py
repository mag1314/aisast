#!/usr/bin/env python3
"""Copy the Python, JavaScript and secrets rule files out of a semgrep-rules checkout
(excluding test fixtures) so they can be passed to `semgrep --config DIR`.

    python benchmark/build_semgrep_ruleset.py /tmp/semgrep-rules /tmp/ruleset
"""
import shutil
import sys
from pathlib import Path

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
count = 0
for sub in ("python", "javascript", "generic/secrets"):
    for f in (src / sub).rglob("*"):
        if f.suffix in (".yaml", ".yml") and not f.name.endswith(".test.yaml") and "fixtures" not in f.parts:
            out = dst / f.relative_to(src)
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(f, out)
            count += 1
print(f"{count} rule files -> {dst}")
