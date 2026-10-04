"""
Security hardening helpers for SentinelBit.

- In-memory rate limiting (brute-force protection for login / 2FA)
- TOTP replay protection (a code can only be used once)
- Username validation and filesystem-safe name sanitizing
- Backup target directory validation (prevents path traversal / arbitrary writes)
- HTTP security headers middleware (CSP, X-Frame-Options, nosniff, ...)
"""
import os
import re
import time
import threading
from collections import defaultdict, deque
from typing import Deque, Dict, List, Tuple

from fastapi import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

import database

# -------------------------------------------------------------
# Rate Limiting
# -------------------------------------------------------------

class RateLimiter:
    """Sliding-window failure counter. Blocks a key after too many failures."""

    def __init__(self, max_failures: int, window_seconds: int):
        self.max_failures = max_failures
        self.window = window_seconds
        self._failures: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> Deque[float]:
        q = self._failures[key]
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def check(self, *keys: str) -> None:
        """Raise HTTP 429 if any of the keys is currently blocked."""
        now = time.time()
        with self._lock:
            for key in keys:
                q = self._prune(key, now)
                if len(q) >= self.max_failures:
                    retry_after = int(self.window - (now - q[0])) + 1
                    raise HTTPException(
                        status_code=429,
                        detail=f"Zu viele Fehlversuche. Bitte in {retry_after} Sekunden erneut versuchen.",
                        headers={"Retry-After": str(retry_after)},
                    )

    def fail(self, *keys: str) -> None:
        now = time.time()
        with self._lock:
            for key in keys:
                self._prune(key, now).append(now)

    def reset(self, *keys: str) -> None:
        with self._lock:
            for key in keys:
                self._failures.pop(key, None)


# Login: max 5 failures / 5 min per account, 20 per IP
login_limiter_user = RateLimiter(max_failures=5, window_seconds=300)
login_limiter_ip = RateLimiter(max_failures=20, window_seconds=300)
# 2FA management endpoints (setup verify / disable): 5 failures / 5 min per user
totp_limiter = RateLimiter(max_failures=5, window_seconds=300)


# -------------------------------------------------------------
# TOTP Replay Protection
# -------------------------------------------------------------

class TotpReplayGuard:
    """Remembers used (user, code) pairs for the validity window so a sniffed code cannot be reused."""

    TTL = 120  # covers valid_window=1 (3 x 30s) with margin

    def __init__(self):
        self._used: Dict[Tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def consume(self, user_id: str, code: str) -> bool:
        """Returns True if the code was not used before (and marks it used)."""
        now = time.time()
        key = (user_id, code.strip())
        with self._lock:
            for k in [k for k, ts in self._used.items() if now - ts > self.TTL]:
                del self._used[k]
            if key in self._used:
                return False
            self._used[key] = now
            return True


totp_replay_guard = TotpReplayGuard()


# -------------------------------------------------------------
# Username validation
# -------------------------------------------------------------

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")


def validate_username(username: str) -> str:
    clean = (username or "").strip().lower()
    if not USERNAME_RE.match(clean) or ".." in clean:
        raise HTTPException(
            status_code=400,
            detail="Ungültiger Benutzername: 3-32 Zeichen, nur a-z, 0-9, Punkt, Unterstrich und Bindestrich.",
        )
    return clean


def safe_filename_component(value: str) -> str:
    """Make any string safe for use inside a filename (no separators, no glob chars, no traversal)."""
    clean = re.sub(r"[^A-Za-z0-9_-]", "_", value or "")
    return clean[:64] or "user"


# -------------------------------------------------------------
# Backup directory validation (path traversal protection)
# -------------------------------------------------------------

def get_allowed_backup_roots() -> List[str]:
    """
    Allowed root directories for automated backups.
    Configure via SENTINELBIT_BACKUP_ROOTS (separated by os.pathsep: ';' on Windows, ':' on Linux).
    Default: <SENTINELBIT_DATA_DIR>
    """
    raw = os.getenv("SENTINELBIT_BACKUP_ROOTS", "").strip()
    roots = [r.strip() for r in raw.split(os.pathsep) if r.strip()] if raw else []
    if not roots:
        roots = [database.DATA_DIR]
    return [os.path.realpath(r) for r in roots]


def default_backup_dir(username: str) -> str:
    return os.path.join(database.DATA_DIR, "backups", safe_filename_component(username))


def validate_backup_dir(target_dir: str) -> str:
    """
    Resolve the target directory (following symlinks) and ensure it lies inside an allowed root
    and is not a dangerous system directory.
    Returns the canonical absolute path or raises HTTP 400.
    """
    if not target_dir or "\x00" in target_dir or ".." in target_dir.replace("/", "\\").split("\\"):
        raise HTTPException(status_code=400, detail="Ungültiges Backup-Verzeichnis")

    candidate = os.path.realpath(os.path.abspath(target_dir.strip()))
    candidate_lower = candidate.lower().replace("/", "\\")

    # Reject dangerous system roots
    system_dirs = [r"c:\windows", r"c:\program files", r"c:\program files (x86)", r"c:\programdata", "/etc", "/bin", "/sbin", "/usr", "/root", "/sys", "/proc", "/dev"]
    for sys_dir in system_dirs:
        if candidate_lower == sys_dir or candidate_lower.startswith(sys_dir + "\\") or candidate_lower.startswith(sys_dir + "/"):
            raise HTTPException(status_code=400, detail="Schreiben in Systemverzeichnisse ist aus Sicherheitsgründen untersagt.")

    for root in get_allowed_backup_roots():
        try:
            if os.path.commonpath([candidate, root]) == root or candidate == root:
                return candidate
        except ValueError:
            # Different drives on Windows
            continue

    allowed = ", ".join(get_allowed_backup_roots())
    raise HTTPException(
        status_code=400,
        detail=f"Backup-Verzeichnis nicht erlaubt. Erlaubte Basisordner: {allowed} (konfigurierbar über SENTINELBIT_BACKUP_ROOTS).",
    )


def is_backup_dir_allowed(target_dir: str) -> bool:
    try:
        validate_backup_dir(target_dir)
        return True
    except HTTPException:
        return False


# -------------------------------------------------------------
# HTTP Security Headers
# -------------------------------------------------------------

# NOTE: 'unsafe-inline' for scripts is still required because index.html uses inline onclick handlers.
# All user-controlled data is no longer placed into those handlers (ID-based lookups only).
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob: https://www.google.com https://*.gstatic.com; "
    "connect-src 'self'; "
    "font-src 'self' data:; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        if request.url.scheme == "https":
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

