"""Minimal, dependency-free Ollama client (REST API on localhost) with structured
JSON output, retries, JSON repair and an on-disk response cache."""
from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional


class OllamaError(RuntimeError):
    pass


class OllamaClient:
    def __init__(self, url: str = "http://localhost:11434", model: str = "qwen2.5-coder:7b", temperature: float = 0.1,
                 num_ctx: int = 8192, timeout: int = 300, cache_dir: Optional[Path] = None):
        self.url = url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.num_ctx = num_ctx
        self.timeout = timeout
        self.cache_dir = cache_dir
        self.stats = {"calls": 0, "cache_hits": 0, "seconds": 0.0, "prompt_tokens": 0, "output_tokens": 0, "errors": 0}
        if cache_dir:
            cache_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ transport
    def _request(self, path: str, payload: Optional[dict] = None, timeout: Optional[int] = None) -> dict:
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.url + path, data=data, method="POST" if data else "GET",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")[:300]
            raise OllamaError(f"Ollama HTTP {e.code}: {body}") from e
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            raise OllamaError(f"Cannot reach Ollama at {self.url}: {e}") from e

    def health(self) -> dict:
        """Returns {ok, version, models, model_present, message}."""
        try:
            ver = self._request("/api/version", timeout=5).get("version", "?")
            models = [m.get("name", "") for m in self._request("/api/tags", timeout=10).get("models", [])]
        except OllamaError as e:
            return {"ok": False, "version": None, "models": [], "model_present": False,
                    "message": f"{e}. Start it with `ollama serve`."}
        present = self.model in models or f"{self.model}:latest" in models or \
            (":" not in self.model and any(m.startswith(self.model + ":") for m in models))
        msg = "ready" if present else f"model '{self.model}' not pulled — run `ollama pull {self.model}`"
        return {"ok": present, "version": ver, "models": models, "model_present": present, "message": msg}

    # ------------------------------------------------------------------ chat
    def chat_json(self, system: str, user: str, schema: Optional[dict] = None, model: Optional[str] = None,
                  retries: int = 2, temperature: Optional[float] = None) -> dict:
        model = model or self.model
        key = hashlib.sha256(json.dumps([model, system, user, schema, temperature], sort_keys=True).encode()).hexdigest()
        cache_file = self.cache_dir / f"{key}.json" if self.cache_dir else None
        if cache_file and cache_file.exists():
            self.stats["cache_hits"] += 1
            return json.loads(cache_file.read_text())
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        last_err = None
        for attempt in range(retries + 1):
            payload = {
                "model": model, "messages": messages, "stream": False,
                "format": schema if (schema and attempt < retries) else "json",
                "options": {"temperature": self.temperature if temperature is None else temperature,
                            "num_ctx": self.num_ctx, "seed": 7},
                "keep_alive": "10m",
            }
            t0 = time.time()
            try:
                resp = self._request("/api/chat", payload)
            except OllamaError as e:
                self.stats["errors"] += 1
                last_err = e
                if "HTTP 4" in str(e) and schema and attempt == 0:
                    continue  # older Ollama without schema support -> plain json mode
                raise
            finally:
                self.stats["seconds"] += time.time() - t0
            self.stats["calls"] += 1
            self.stats["prompt_tokens"] += resp.get("prompt_eval_count", 0) or 0
            self.stats["output_tokens"] += resp.get("eval_count", 0) or 0
            content = (resp.get("message") or {}).get("content", "")
            parsed = parse_json(content)
            if parsed is not None:
                if cache_file:
                    cache_file.write_text(json.dumps(parsed))
                return parsed
            last_err = OllamaError(f"model returned non-JSON output: {content[:200]!r}")
            messages = messages + [{"role": "assistant", "content": content[:2000]},
                                   {"role": "user", "content": "That was not valid JSON. Reply with ONLY the JSON object."}]
        raise last_err or OllamaError("unknown error")


def parse_json(text: str) -> Optional[dict]:
    text = (text or "").strip()
    if not text:
        return None
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    try:
        val = json.loads(text)
        return val if isinstance(val, dict) else {"items": val}
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            cleaned = re.sub(r",\s*([}\]])", r"\1", text[start:end + 1])
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError:
                return None
    return None
