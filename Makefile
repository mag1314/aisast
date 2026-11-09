.PHONY: install test demo demo-offline benchmark-demo
install:        ; python3 -m pip install -e ".[dev]"
test:           ; python3 -m pytest -q tests
demo:           ; ./demo/run_demo.sh
demo-offline:   ; ./demo/run_demo.sh --no-ai
benchmark-demo: ; python3 benchmark/run_benchmark.py demo --semgrep-config p/default
