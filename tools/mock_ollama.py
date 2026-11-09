"""Ollama API test double — FOR TESTING THE PIPELINE ONLY.

Implements /api/version, /api/tags and /api/chat with canned, deterministic replies so
CI can exercise every AI code path (HTTP transport, JSON schemas, caching, retries,
hallucination filtering, fix validation + self-correction, review gate) without a GPU.
It contains NO security intelligence: never use it to judge detection or fix quality.

    python tools/mock_ollama.py --port 11434
"""
from __future__ import annotations

import argparse
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"fix_calls": 0}


def reply(system: str, user: str) -> dict:
    if user.startswith("Review this static-analysis finding"):
        low = "Detector confidence: low" in user
        return {"verdict": "uncertain" if low else "true_positive", "confidence": 0.5 if low else 0.9,
                "severity": re.search(r"Reported severity: (\w+)", user).group(1),
                "explanation": "[mock] canned explanation", "exploit_scenario": "[mock] canned scenario",
                "root_cause": "[mock]", "remediation": "[mock] canned remediation", "secure_example": ""}
    if user.startswith("Audit the following"):
        first = re.search(r"^\s*(?:>>)?\s*(\d+) \| (.+)$", user, re.M)
        out = [{"line": 99999, "category": "logic", "cwe": "CWE-840", "title": "hallucinated", "severity": "high",
                "confidence": 0.95, "evidence": "this text does not exist in the file", "description": "[mock] should be dropped"}]
        if first:
            out.append({"line": int(first.group(1)), "category": "logic", "cwe": "CWE-840", "title": "[mock] canned finding",
                        "severity": "low", "confidence": 0.9, "evidence": first.group(2).strip(), "description": "[mock]"})
        return {"findings": out}
    if user.startswith("You are fixing security vulnerabilities"):
        STATE["fix_calls"] += 1
        code = re.search(r"Code to replace \(lines \d+-\d+\):\n```\w*\n(.*?)\n```", user, re.S).group(1)
        if "IMPORTANT:" not in user:
            return {"fixed_code": code + "\n    )(", "summary": "[mock] broken on purpose", "new_imports": []}
        return {"fixed_code": code + "\n", "summary": "[mock] unchanged", "new_imports": []}
    if user.startswith("Review a proposed security patch"):
        return {"fixes_vulnerability": True, "preserves_behavior": True, "introduces_issues": False, "concerns": ""}
    if user.startswith("You are writing the executive summary"):
        return {"executive_summary": "[mock] canned summary", "key_risks": ["[mock]"], "recommended_actions": ["[mock]"]}
    if user.startswith("A developer has a question"):
        return {"answer": "[mock] canned answer"}
    return {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/version":
            return self._send({"version": "0.0.0-mock"})
        if self.path == "/api/tags":
            return self._send({"models": [{"name": "mock-model:latest"}, {"name": "qwen2.5-coder:7b"}]})
        self._send({"error": "not found"}, 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n) or b"{}")
        if self.path != "/api/chat":
            return self._send({"error": "not found"}, 404)
        msgs = req.get("messages", [])
        system = next((m["content"] for m in msgs if m["role"] == "system"), "")
        user = next((m["content"] for m in msgs if m["role"] == "user"), "")
        content = json.dumps(reply(system, user))
        self._send({"model": req.get("model"), "message": {"role": "assistant", "content": content}, "done": True,
                    "prompt_eval_count": len(user) // 4, "eval_count": len(content) // 4})


def serve(port: int = 11434) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=11434)
    a = ap.parse_args()
    print(f"mock Ollama on http://127.0.0.1:{a.port} (TEST DOUBLE — no real model)")
    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()
