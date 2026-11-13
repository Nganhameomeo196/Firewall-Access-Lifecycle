"""Local-only signed-cookie session; NOT a production IAM implementation."""
from __future__ import annotations
from collections import defaultdict, deque
from pathlib import Path
from secrets import token_bytes
from time import time
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import Request, HTTPException

SESSION_HOURS = 8
_failed: dict[str, deque[float]] = defaultdict(deque)


def serializer(root: Path) -> URLSafeTimedSerializer:
    secret_file = root / "runtime" / ".local_session_key"
    secret_file.parent.mkdir(parents=True, exist_ok=True)
    if not secret_file.exists():
        secret_file.write_bytes(token_bytes(48))
        try: secret_file.chmod(0o600)
        except OSError: pass
    return URLSafeTimedSerializer(secret_file.read_bytes(), salt="accessflow-v2-local")


def create_session(actor_id: int, root: Path) -> str:
    return serializer(root).dumps({"id": int(actor_id)})


def decode_session(request: Request, root: Path) -> int:
    value = request.cookies.get("af_session")
    if not value:
        raise HTTPException(status_code=401, detail="Cần đăng nhập để sử dụng hệ thống")
    try:
        data = serializer(root).loads(value, max_age=SESSION_HOURS * 3600)
        return int(data["id"])
    except (BadSignature, SignatureExpired, TypeError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại")


def guard_login(address: str):
    entries = _failed[address]
    now = time()
    while entries and now - entries[0] > 300:
        entries.popleft()
    if len(entries) >= 10:
        raise HTTPException(status_code=429, detail="Đăng nhập thất bại nhiều lần. Thử lại sau ít phút")


def failed_login(address: str):
    guard_login(address)
    _failed[address].append(time())


def successful_login(address: str):
    _failed.pop(address, None)
