"""Login, sessions and CSRF for the review dashboard.

The board is public and read-only. This module guards the one surface that is neither:
`/admin`, where a submitted host is approved onto the board or rejected. Approving a
target makes this service start making outbound requests to it and publishes it to every
consumer of the API, so the bar is higher than "hard to guess".

Five decisions, each one because the obvious alternative has a hole in it.

**No default password, and no panel without one.** With `admin_password_hash` unset the
routes are not registered at all and `/admin` is a 404 — not a login form, which would
advertise the surface. A default credential on a self-hosted service is a published
credential.

**scrypt, from the standard library.** No new dependency for one hash. Parameters are
stored alongside the digest so they can be raised later without invalidating existing
hashes, and the stored form carries its own salt.

**Sessions in memory, not signed cookies.** A signed cookie cannot be revoked; a dict
can. The cost is that sessions end when the process restarts, which for a single-process
service that redeploys by restart is the correct trade — and a restart is exactly when
you want sessions gone.

**CSRF on every mutation.** The session cookie is `SameSite=Strict`, which stops
cross-site form posts in every browser that honours it, and the token is the belt to that
suspenders: `SameSite` is a browser behaviour, and an approval endpoint should not depend
on the client's correctness.

**Failures are counted, successes are not.** Rate limiting is per client address over a
window, and a correct password clears the counter. Without that, a legitimate admin who
mistypes twice is locked out by an attacker's traffic.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass, field

log = logging.getLogger("epic_status.admin")

#: scrypt cost. Memory is the binding constraint, not time: scrypt needs roughly
#: `128 * n * r` bytes, so n=2**14 with r=8 is 16 MB per hash. That matters because this
#: service runs under `MemoryHigh=192M` / `MemoryMax=256M` beside a live mainnet node — a
#: login must not be the allocation that trips the cgroup.
#:
#: n=2**15 was the first choice and failed outright: 32 MB exceeds OpenSSL's default
#: `maxmem` and `hashlib.scrypt` raises "memory limit exceeded" rather than degrading. The
#: limit has to be raised explicitly, which is what `_MAXMEM` is for.
#:
#: 16 MB is not a compromise on security here. The password is 192 bits of `token_urlsafe`
#: entropy, so it is not guessable at any cost per guess; scrypt is guarding only against
#: an attacker who has already stolen the hash, and against that the work factor buys time
#: rather than safety.
_N = 2**14
_R = 8
_P = 1
_DKLEN = 32

#: Ceiling handed to OpenSSL, with headroom over `128 * _N * _R` so a future raise of the
#: cost does not turn into the same opaque ValueError.
_MAXMEM = 64 * 1024 * 1024

#: How long a session lives without being renewed. Short enough that a forgotten open tab
#: is not a standing key; long enough to review a queue without logging in twice.
SESSION_TTL_S = 8 * 3600

#: Login attempts allowed per address per window before the address is refused.
MAX_ATTEMPTS = 5
ATTEMPT_WINDOW_S = 900


def hash_password(password: str) -> str:
    """Produce the stored form: `scrypt$n$r$p$salt$digest`, base64 for the two binaries.

    Parameters travel with the digest so raising them later does not invalidate what is
    already deployed — `verify_password` reads them from the stored string rather than
    from these constants.
    """
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_N,
        r=_R,
        p=_P,
        dklen=_DKLEN,
        maxmem=_MAXMEM,
    )
    return "scrypt${}${}${}${}${}".format(
        _N,
        _R,
        _P,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check against the stored form.

    Returns False rather than raising on a malformed stored value: a broken
    `ADMIN_PASSWORD_HASH` must fail closed as "wrong password", never as a traceback that
    tells the caller the credential is misconfigured.
    """
    try:
        scheme, n_s, r_s, p_s, salt_b64, digest_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest_b64)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=base64.b64decode(salt_b64),
            n=int(n_s),
            r=int(r_s),
            p=int(p_s),
            dklen=len(expected),
            maxmem=_MAXMEM,
        )
    except Exception:
        log.warning("admin password hash is malformed; refusing every login")
        return False
    return hmac.compare_digest(actual, expected)


@dataclass
class Session:
    token: str
    csrf: str
    created_at: float
    user: str


@dataclass
class Sessions:
    """In-memory session and rate-limit state for one process."""

    _live: dict[str, Session] = field(default_factory=dict)
    _failures: dict[str, list[float]] = field(default_factory=dict)

    # ----------------------------------------------------------------- sessions

    def create(self, user: str) -> Session:
        session = Session(
            token=secrets.token_urlsafe(32),
            csrf=secrets.token_urlsafe(32),
            created_at=time.monotonic(),
            user=user,
        )
        self._live[session.token] = session
        return session

    def get(self, token: str | None) -> Session | None:
        """Resolve a cookie to a live session, expiring it if it is too old.

        Expiry is checked on read rather than swept on a timer: there is no volume here
        to justify a background task, and a session that is never read again costs one
        dict entry until the process restarts.
        """
        if not token:
            return None
        session = self._live.get(token)
        if session is None:
            return None
        if time.monotonic() - session.created_at > SESSION_TTL_S:
            del self._live[token]
            return None
        return session

    def destroy(self, token: str | None) -> None:
        if token:
            self._live.pop(token, None)

    def valid_csrf(self, session: Session, submitted: str | None) -> bool:
        return bool(submitted) and hmac.compare_digest(session.csrf, submitted or "")

    # -------------------------------------------------------------- rate limit

    def locked_out(self, client: str) -> bool:
        return len(self._recent_failures(client)) >= MAX_ATTEMPTS

    def record_failure(self, client: str) -> None:
        self._failures.setdefault(client, []).append(time.monotonic())

    def clear_failures(self, client: str) -> None:
        """A correct password clears the counter.

        Without this an attacker's failed guesses against a shared proxy address lock out
        the legitimate admin behind it, which turns a rate limit into a denial of service.
        """
        self._failures.pop(client, None)

    def _recent_failures(self, client: str) -> list[float]:
        now = time.monotonic()
        kept = [t for t in self._failures.get(client, []) if now - t < ATTEMPT_WINDOW_S]
        if kept:
            self._failures[client] = kept
        else:
            self._failures.pop(client, None)
        return kept


def check_credentials(
    *, user: str, password: str, expected_user: str, stored_hash: str
) -> bool:
    """Both halves compared in constant time.

    The username is compared with `compare_digest` as well, so the response time does not
    reveal whether the account name was right. scrypt runs regardless for the same reason:
    returning early on an unknown username makes "wrong user" measurably faster than
    "wrong password", which is a free oracle for enumerating the account name.
    """
    user_ok = hmac.compare_digest(user.encode("utf-8"), expected_user.encode("utf-8"))
    password_ok = verify_password(password, stored_hash)
    return user_ok and password_ok
