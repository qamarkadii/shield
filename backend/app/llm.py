"""
Connection to the DeepSeek server. Every setting comes from .env (never from code):

    CHAT_PROVIDER=auto            auto = DeepSeek first, built-in assistant if DeepSeek fails (recommended)
                                  deepseek = DeepSeek only   |   builtin = built-in assistant only (no internet needed)
    DEEPSEEK_API_KEY=sk-...       your key from platform.deepseek.com
    DEEPSEEK_BASE_URL=https://api.deepseek.com
    DEEPSEEK_MODEL=deepseek-flash
    DEEPSEEK_FALLBACK_MODEL=deepseek-v4-pro     tried once if the main model is busy (leave empty to skip)
    DEEPSEEK_FIRST_TOKEN_SECONDS=8              give up if no words arrive within this time
    DEEPSEEK_TOTAL_SECONDS=45                   hard limit for one answer

Test from the command line:   python -m backend.app.llm
"""

import json
import os
import queue
import socket
import threading
import time

import requests
from dotenv import load_dotenv

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
load_dotenv(os.path.join(ROOT, ".env"))


_down_until = 0.0          # after DeepSeek fails, skip it for a while so every message isn't slow
PAUSE_SECONDS = 120


class LLMError(Exception):
    """DeepSeek could not give an answer (busy, wrong key, no balance, timeout...)."""


def settings() -> dict:
    env = os.environ.get
    provider = (env("CHAT_PROVIDER") or "").strip().lower()
    if provider not in ("auto", "deepseek", "builtin"):
        # older .env files: SHIELD_EXTERNAL_CHAT_ENABLED=1 meant "use DeepSeek"
        provider = "auto" if env("SHIELD_EXTERNAL_CHAT_ENABLED", "1") == "1" else "builtin"
    return {
        "provider": provider,
        "key": (env("DEEPSEEK_API_KEY") or "").strip(),
        "url": (env("DEEPSEEK_BASE_URL") or "https://api.deepseek.com").rstrip("/") + "/chat/completions",
        "models": [m for m in [(env("DEEPSEEK_MODEL") or "deepseek-flash").strip(),
                               (env("DEEPSEEK_FALLBACK_MODEL", "deepseek-v4-pro") or "").strip()] if m],
        "first_token": float(env("DEEPSEEK_FIRST_TOKEN_SECONDS") or 8),
        "total": float(env("DEEPSEEK_TOTAL_SECONDS") or 45),
    }


def _abort(resp):
    """Close a streaming response without waiting: the reader thread may be blocked in a read."""
    try:
        sock = getattr(getattr(resp.raw, "_connection", None), "sock", None)
        if sock:
            sock.shutdown(socket.SHUT_RDWR)          # wakes up a blocked read
    except Exception:
        pass
    threading.Thread(target=resp.close, daemon=True).start()


def _stream_one(cfg: dict, model: str, messages: list[dict], max_tokens: int):
    body = {"model": model, "messages": messages, "stream": True, "temperature": 0.3,
            "max_tokens": max_tokens, "thinking": {"type": "disabled"}}
    start = time.monotonic()
    got_text = False
    try:
        resp = requests.post(cfg["url"], json=body, stream=True, timeout=(6, cfg["first_token"]),
                             headers={"Authorization": f"Bearer {cfg['key']}"})
    except requests.RequestException as e:
        raise LLMError(f"unreachable: {e.__class__.__name__}") from e
    # When DeepSeek is overloaded it keeps the connection open with ": keep-alive" lines and no words.
    # A reader thread passes lines through a queue, and we wait on it with hard deadlines,
    # so the chat never hangs however the server behaves.
    if resp.status_code != 200:
        text = resp.text[:200]
        resp.close()
        raise LLMError(f"HTTP {resp.status_code}: {text}")
    lines: queue.Queue = queue.Queue()

    def reader():
        try:
            for raw in resp.iter_lines(chunk_size=None, decode_unicode=True):
                lines.put(("line", raw))
            lines.put(("end", None))
        except Exception as e:                       # connection closed / reset
            lines.put(("error", e))

    threading.Thread(target=reader, daemon=True).start()
    try:
        while True:
            deadline = start + (cfg["total"] if got_text else min(cfg["first_token"], cfg["total"]))
            wait = deadline - time.monotonic()
            if wait <= 0:
                if got_text:
                    return                           # keep what was already sent
                raise LLMError(f"no answer within {cfg['first_token']:.0f}s (server busy)")
            try:
                kind, raw = lines.get(timeout=wait)
            except queue.Empty:
                continue                             # loop re-checks the deadline
            if kind == "end":
                break
            if kind == "error":
                if got_text:
                    return
                raise LLMError(f"connection failed: {raw.__class__.__name__}")
            if not raw or not raw.startswith("data:"):
                continue
            data = raw[5:].strip()
            if data == "[DONE]":
                break
            try:
                delta = json.loads(data)["choices"][0]["delta"].get("content")
            except (ValueError, KeyError, IndexError, TypeError):
                continue
            if delta:
                got_text = True
                yield delta
    finally:
        _abort(resp)
    if not got_text:
        raise LLMError("empty answer")


def stream_chat(messages: list[dict], max_tokens: int = 900):
    """Yields pieces of DeepSeek's answer. Raises LLMError (before any text) if no model can answer."""
    cfg = settings()
    if cfg["provider"] == "builtin":
        raise LLMError("CHAT_PROVIDER=builtin")
    if not cfg["key"]:
        raise LLMError("DEEPSEEK_API_KEY is missing in .env")
    global _down_until
    if time.monotonic() < _down_until:
        raise LLMError(f"DeepSeek paused for {(_down_until - time.monotonic()):.0f}s after a failure")
    errors = []
    for model in cfg["models"]:
        sent = False
        try:
            for piece in _stream_one(cfg, model, messages, max_tokens):
                sent = True
                yield piece
            return
        except LLMError as e:
            if sent:
                return
            errors.append(f"{model}: {e}")
            print(f"[chat] DeepSeek {model} failed: {e}")
            if any(x in str(e) for x in ("HTTP 401", "HTTP 402", "no answer within")):
                break        # wrong key / no balance / server stalled: the other model won't help, answer now
    _down_until = time.monotonic() + PAUSE_SECONDS
    print(f"[chat] DeepSeek unavailable, built-in assistant for the next {PAUSE_SECONDS}s")
    raise LLMError("; ".join(errors) or "no model configured")


if __name__ == "__main__":
    cfg = settings()
    print("Provider:", cfg["provider"], "| models:", cfg["models"], "| key set:", bool(cfg["key"]))
    try:
        t = time.monotonic()
        text = "".join(stream_chat([{"role": "user", "content": "Say hello in one short sentence."}], 40))
        print(f"OK in {time.monotonic() - t:.1f}s:", text)
    except LLMError as e:
        print("DeepSeek not available ->", e, "\nThe chat will use the built-in assistant (assistant.py).")
