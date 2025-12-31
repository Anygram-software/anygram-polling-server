from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import pathlib
import shutil
import subprocess
import time
import uuid
from collections import deque
from typing import Any, Deque, Dict, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

# Все переменные можно также задать в вашем окружении. 

ANYGRAM_API_KEY = "changethis123" # ВАШ АПИ КЛЮЧ СОФТА
DEFAULT_PORT = 4546 # ПОРТ НА КОТОРОМ ПОДНЯТЬ ПУЛЛИНГ-СЕРВЕР

DEFAULT_ALLOW_API_ONLY = False # Если True то на порту будет доступен только API интерфейсе /panel_api/, Веб-интерфейс будет запрещен к получению
POLLING_BIND_ALL = False # Если False то сервер работает на локалхосте 127.0.0.1, если True то доступен наружу в интернет (0.0.0.0)
ANYGRAM_POLLING_SSL_SELF_SIGNED = False # Включить ли HTTPS на самоподнисном сертификате (генерируется автоматически)

# Апи ключ для доступа к пуллинг-серверу (НЕ К СОФТУ),
# в большинстве случаев лучше оставить пустым тк сам Anygram-клиент и так отвергает запросы с неверным ANYGRAM_API_KEY,
# если POLLING_API_KEY установлен то будет требоваться апи ключ в хеадерсе для подключения к пуллинг-серверу (не софту) то есть дополнительный слой защиты на уровне сервера.
POLLING_API_KEY = ""


# Настройки протокола
DEFAULT_WINDOW_SEC = 200
DEFAULT_RESEND_SEC = 60
DEFAULT_WAIT_SEC = 30
DEFAULT_RESPONSE_TTL_SEC = 300
DEFAULT_LONG_POLL_SEC = 50


# Можете указать свой путь к своим сертификатам, если не найдутся то скрипт сгенерирует автоматически при включенном ssl (см. _generate_self_signed() )
DEFAULT_SSL_DIR = "data/polling_ssl"
ANYGRAM_POLLING_SSL_CERT = "anygram_ssl_cert.pem"
ANYGRAM_POLLING_SSL_KEY = "anygram_ssl_key.pem"


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "")
    if not raw:
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except Exception:
        value = default
    if value < minimum:
        return default
    return value


def _env_str(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or "").strip()


POLLING_WINDOW_SEC = _env_int("ANYGRAM_POLLING_WINDOW_SEC", DEFAULT_WINDOW_SEC)
POLLING_RESEND_SEC = _env_int("ANYGRAM_POLLING_RESEND_SEC", DEFAULT_RESEND_SEC)
POLLING_WAIT_SEC = _env_int("ANYGRAM_POLLING_WAIT_SEC", DEFAULT_WAIT_SEC)
POLLING_RESPONSE_TTL_SEC = _env_int("ANYGRAM_POLLING_RESPONSE_TTL_SEC", DEFAULT_RESPONSE_TTL_SEC)
POLLING_LONG_POLL_SEC = _env_int("ANYGRAM_POLLING_LONG_POLL_SEC", DEFAULT_LONG_POLL_SEC)
POLLING_SECRET = _env_str("ANYGRAM_POLLING_SECRET", ANYGRAM_API_KEY)
POLLING_API_KEY = _env_str("ANYGRAM_POLLING_API_KEY", POLLING_API_KEY)
POLLING_PORT = _env_int("ANYGRAM_POLLING_PORT", DEFAULT_PORT)
POLLING_BIND_ALL = _env_bool("ANYGRAM_POLLING_BIND_ALL", POLLING_BIND_ALL)
POLLING_HOST = _env_str("ANYGRAM_POLLING_HOST", "") or ("0.0.0.0" if POLLING_BIND_ALL else "127.0.0.1")
POLLING_ALLOW_API_ONLY = _env_bool("ANYGRAM_POLLING_ALLOW_API_ONLY", DEFAULT_ALLOW_API_ONLY)
POLLING_SSL_SELF_SIGNED = _env_bool("ANYGRAM_POLLING_SSL_SELF_SIGNED", ANYGRAM_POLLING_SSL_SELF_SIGNED)
POLLING_SSL_CERT = _env_str("ANYGRAM_POLLING_SSL_CERT", ANYGRAM_POLLING_SSL_CERT)
POLLING_SSL_KEY = _env_str("ANYGRAM_POLLING_SSL_KEY", ANYGRAM_POLLING_SSL_KEY)
POLLING_SSL_DIR = pathlib.Path(_env_str("ANYGRAM_POLLING_SSL_DIR", DEFAULT_SSL_DIR)).resolve()

app = FastAPI()

_pending: Deque[dict] = deque()
_inflight: Dict[str, Tuple[int, dict]] = {}
_pending_event = asyncio.Event()
_shutdown_event = asyncio.Event()
_last_poll_ok_ts = 0
_last_poll_auth_error: Tuple[int, str] | None = None

_recent_ids: Dict[str, int] = {}
_recent_queue: Deque[Tuple[int, str]] = deque()
_recent_lock = asyncio.Lock()

_waiters: Dict[str, asyncio.Future] = {}
_responses: Dict[str, Tuple[int, dict]] = {}
_response_queue: Deque[Tuple[int, str]] = deque()
_wait_lock = asyncio.Lock()


def _ssl_paths() -> tuple[str | None, str | None]:
    if POLLING_SSL_CERT and POLLING_SSL_KEY:
        cert = pathlib.Path(POLLING_SSL_CERT).expanduser()
        key = pathlib.Path(POLLING_SSL_KEY).expanduser()
        if cert.exists() and key.exists():
            return str(cert), str(key)
        if not POLLING_SSL_SELF_SIGNED:
            return None, None
    if not POLLING_SSL_SELF_SIGNED:
        return None, None

    try:
        POLLING_SSL_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        return None, None

    cert_path = POLLING_SSL_DIR / "cert.pem"
    key_path = POLLING_SSL_DIR / "key.pem"
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)

    if _generate_self_signed(cert_path, key_path):
        return str(cert_path), str(key_path)
    return None, None


def _generate_self_signed(cert_path: pathlib.Path, key_path: pathlib.Path) -> bool:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import ipaddress

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Anygram Polling"),
        ])
        san = x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ])
        from datetime import datetime, timedelta

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )
        key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        return True
    except Exception:
        pass

    openssl = shutil.which("openssl")
    if not openssl:
        return False
    try:
        cmd = [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "3650",
            "-subj",
            "/CN=Anygram Polling",
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return cert_path.exists() and key_path.exists()
    except Exception:
        return False


def _mark_poll_ok(now: int) -> None:
    global _last_poll_ok_ts, _last_poll_auth_error
    _last_poll_ok_ts = now
    _last_poll_auth_error = None


def _mark_poll_auth_error(now: int, reason: str) -> None:
    global _last_poll_auth_error
    _last_poll_auth_error = (now, reason)


def _current_poll_auth_error(now: int) -> Tuple[int, str] | None:
    err = _last_poll_auth_error
    if not err:
        return None
    ts, reason = err
    if now - ts > POLLING_WINDOW_SEC:
        return None
    if ts <= _last_poll_ok_ts:
        return None
    return err


def _expected_signature(secret: str, ts: int, req_id: str) -> str:
    msg = f"{ts}:{req_id}"
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


def _purge_old(now: int, window_sec: int) -> None:
    while _recent_queue and now - _recent_queue[0][0] > window_sec:
        old_ts, old_id = _recent_queue.popleft()
        if _recent_ids.get(old_id) == old_ts:
            del _recent_ids[old_id]


def _purge_responses(now: int, ttl_sec: int) -> None:
    while _response_queue and now - _response_queue[0][0] > ttl_sec:
        old_ts, old_id = _response_queue.popleft()
        if _responses.get(old_id, (None, None))[0] == old_ts:
            del _responses[old_id]


def _signed_response(payload: dict) -> JSONResponse:
    ts = int(time.time())
    req_id = str(uuid.uuid4())
    sig = _expected_signature(POLLING_SECRET, ts, req_id)
    return JSONResponse(
        payload,
        headers={
            "X-Anygram-Timestamp": str(ts),
            "X-Anygram-Request-Id": req_id,
            "X-Anygram-Signature": sig,
        },
    )


def _sync_pending_event() -> None:
    if _pending:
        _pending_event.set()
    else:
        _pending_event.clear()


@app.on_event("startup")
async def _on_startup() -> None:
    _shutdown_event.clear()


@app.on_event("shutdown")
async def _on_shutdown() -> None:
    _shutdown_event.set()
    _pending_event.set()


def _take_items(max_items: int) -> list[dict]:
    now = int(time.time())
    resend_after = POLLING_RESEND_SEC
    items: list[dict] = []

    for rid, (ts_sent, item) in list(_inflight.items()):
        if len(items) >= max_items:
            break
        if now - ts_sent >= resend_after:
            _inflight[rid] = (now, item)
            items.append(item)

    while len(items) < max_items and _pending:
        item = dict(_pending.popleft())
        rid = item.get("id") or str(uuid.uuid4())
        item["id"] = rid
        _inflight[rid] = (now, item)
        items.append(item)

    _sync_pending_event()
    return items


def _filter_forward_headers(headers: Any) -> dict:
    drop = {
        "host",
        "connection",
        "content-length",
        "accept-encoding",
        "transfer-encoding",
    }
    out = {}
    try:
        for k, v in headers.items():
            name = str(k)
            if name.lower() in drop or name.lower().startswith("x-anygram-"):
                continue
            out[name] = str(v)
    except Exception:
        return {}
    return out


def _store_response(rid: str, payload: dict) -> None:
    now = int(time.time())
    _responses[rid] = (now, payload)
    _response_queue.append((now, rid))
    fut = _waiters.pop(rid, None)
    if fut is not None and not fut.done():
        fut.set_result(payload)


def _response_to_http(resp: dict) -> Response:
    status = int(resp.get("status_code") or (200 if resp.get("ok", True) else 500))
    headers = resp.get("headers") or {}
    body = resp.get("body")
    if resp.get("body_is_json"):
        return JSONResponse(body, status_code=status, headers=headers)
    if resp.get("body_is_base64") and body is not None:
        try:
            raw = base64.b64decode(body)
        except Exception:
            raw = b""
        return Response(content=raw, status_code=status, headers=headers)
    if body is None:
        if resp.get("error"):
            return JSONResponse({"ok": False, "error": resp.get("error")}, status_code=status, headers=headers)
        return Response(status_code=status, headers=headers)
    return PlainTextResponse(str(body), status_code=status, headers=headers)


@app.post("/anygram_poll")
async def anygram_poll(request: Request) -> JSONResponse:
    headers = request.headers
    ts_raw = headers.get("x-anygram-timestamp")
    req_id = headers.get("x-anygram-request-id")
    sig = headers.get("x-anygram-signature")

    if not ts_raw or not req_id or not sig:
        _mark_poll_auth_error(int(time.time()), "missing_headers")
        return JSONResponse({"ok": False, "error": "missing_headers"}, status_code=400)

    try:
        ts = int(ts_raw)
    except Exception:
        _mark_poll_auth_error(int(time.time()), "bad_timestamp")
        return JSONResponse({"ok": False, "error": "bad_timestamp"}, status_code=400)

    window_sec = POLLING_WINDOW_SEC
    now = int(time.time())
    if abs(now - ts) > window_sec:
        _mark_poll_auth_error(now, "timestamp_out_of_window")
        return JSONResponse({"ok": False, "error": "timestamp_out_of_window"}, status_code=401)

    expected = _expected_signature(POLLING_SECRET, ts, req_id)
    if not hmac.compare_digest(expected, sig):
        _mark_poll_auth_error(now, "bad_signature")
        return JSONResponse({"ok": False, "error": "bad_signature"}, status_code=401)

    async with _recent_lock:
        _purge_old(now, window_sec)
        if req_id in _recent_ids:
            return JSONResponse({"ok": False, "error": "duplicate_request_id"}, status_code=409)
        _recent_ids[req_id] = ts
        _recent_queue.append((ts, req_id))
        _mark_poll_ok(now)

    try:
        payload = await request.json()
    except Exception:
        payload = {}

    max_items = 1
    try:
        max_items = int(payload.get("max_items", 1) or 1)
    except Exception:
        max_items = 1
    max_items = max(1, max_items)
    long_poll_sec = 0
    try:
        long_poll_sec = int(payload.get("long_poll_sec") or 0)
    except Exception:
        long_poll_sec = 0
    if long_poll_sec > 0:
        long_poll_sec = min(long_poll_sec, POLLING_LONG_POLL_SEC)

    responses = payload.get("responses") or []
    if isinstance(responses, list):
        for response in responses:
            if not isinstance(response, dict):
                continue
            rid = response.get("id")
            if not rid:
                continue
            if rid in _inflight:
                del _inflight[rid]
            _store_response(str(rid), response)

    acks = payload.get("acks") or []
    if isinstance(acks, list):
        for ack in acks:
            if not isinstance(ack, dict):
                continue
            rid = ack.get("id")
            if rid in _inflight:
                del _inflight[rid]

    _purge_responses(now, POLLING_RESPONSE_TTL_SEC)

    items = _take_items(max_items)
    if not items and long_poll_sec > 0:
        if _shutdown_event.is_set():
            resp_payload = {
                "ok": True,
                "requests": [],
                "server_time": int(time.time()),
            }
            return _signed_response(resp_payload)
        wait_sec = long_poll_sec
        if _inflight:
            resend_after = POLLING_RESEND_SEC
            next_due = None
            for ts_sent, _ in _inflight.values():
                due_in = resend_after - (now - ts_sent)
                if due_in <= 0:
                    next_due = 0
                    break
                if next_due is None or due_in < next_due:
                    next_due = due_in
            if next_due is not None:
                wait_sec = min(wait_sec, max(0, int(next_due)))
        if wait_sec > 0:
            if _shutdown_event.is_set():
                wait_sec = 0
            else:
                pending_task = asyncio.create_task(_pending_event.wait())
                shutdown_task = asyncio.create_task(_shutdown_event.wait())
                done, pending = await asyncio.wait(
                    {pending_task, shutdown_task},
                    timeout=wait_sec,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in pending:
                    task.cancel()
                if shutdown_task in done:
                    wait_sec = 0
        if _shutdown_event.is_set():
            items = []
        else:
            items = _take_items(max_items)
    resp_payload = {
        "ok": True,
        "requests": items,
        "server_time": int(time.time()),
    }
    return _signed_response(resp_payload)


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def root_proxy(path: str, request: Request) -> Response:
    err = _current_poll_auth_error(int(time.time()))
    if err:
        return JSONResponse({"ok": False, "error": "polling_auth_failed", "reason": err[1]}, status_code=401)

    if POLLING_ALLOW_API_ONLY:
        if not path.startswith("panel_api/") and path != "panel_api":
            return JSONResponse({"ok": False, "error": "not_allowed"}, status_code=403)

    api_key = POLLING_API_KEY
    if api_key:
        if request.headers.get("Polling-Authorization") != api_key:
            return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)

    rid = str(uuid.uuid4())
    query = dict(request.query_params)
    headers = _filter_forward_headers(request.headers)

    raw = await request.body()
    body = None
    body_text = None
    body_is_text = False
    if raw:
        try:
            body = await request.json()
        except Exception:
            body_text = raw.decode("utf-8", errors="replace")
            body_is_text = True

    path = f"/{path}" if path else "/"
    item = {
        "id": rid,
        "method": request.method,
        "path": path,
        "query": query,
        "headers": headers,
        "created_at": int(time.time()),
    }
    if body_is_text:
        item["body_text"] = body_text
        item["body_is_text"] = True
    elif body is not None:
        item["body"] = body

    _pending.append(item)
    _sync_pending_event()

    wait_sec = POLLING_WAIT_SEC
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    async with _wait_lock:
        _waiters[rid] = fut

    try:
        resp_payload = await asyncio.wait_for(fut, timeout=wait_sec)
        return _response_to_http(resp_payload)
    except asyncio.TimeoutError:
        return JSONResponse({"ok": False, "error": "timeout", "request_id": rid}, status_code=504)
    finally:
        _waiters.pop(rid, None)


if __name__ == "__main__":
    try:
        import uvicorn
    except Exception as exc:
        print(f"[polling_server] uvicorn missing: {exc}")
        raise
    certfile, keyfile = _ssl_paths()
    try:
        import inspect

        cfg_kwargs = {
            "host": POLLING_HOST,
            "port": POLLING_PORT,
            "log_level": "info",
            "ssl_certfile": certfile,
            "ssl_keyfile": keyfile,
        }
        sig = inspect.signature(uvicorn.Config)
        if "timeout_graceful_shutdown" in sig.parameters:
            cfg_kwargs["timeout_graceful_shutdown"] = 0
        elif "graceful_timeout" in sig.parameters:
            cfg_kwargs["graceful_timeout"] = 0

        config = uvicorn.Config(app, **cfg_kwargs)
        server = uvicorn.Server(config)
        server.run()
    except Exception:
        uvicorn.run(
            app,
            host=POLLING_HOST,
            port=POLLING_PORT,
            log_level="info",
            ssl_certfile=certfile,
            ssl_keyfile=keyfile,
        )
