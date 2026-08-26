"""Authentication use cases and their transaction boundaries."""

from __future__ import annotations

from dataclasses import dataclass
import hmac
import secrets as _secrets

from .. import crypto, db as database, demo as demo_seed, email as email_sender, ratestore
from ..config import get_settings
from ..domain.identity import session as sess
from ..domain.identity.access import _is_machine_email, _norm_email
from . import signup


CLI_TOKEN_TTL = 30 * 24 * 3600      # identity token lifetime for the CLI
EMAIL_CODE_TTL = 10 * 60  # seconds a code stays valid
MAX_OTP_ATTEMPTS = 5  # invalidate a code after this many wrong guesses (brute-force guard)
OTP_NS = "otp"
OTP_START_NS = "otp_start"
OTP_START_WINDOW_S = 900      # 15 minutes
OTP_START_MAX_PER_EMAIL = 5   # code requests for one inbox per window (caps bombing a single victim)
OTP_START_MAX_PER_IP = 30     # code requests from one IP per window (looser — offices/NAT share an IP)


class EmailAuthError(Exception):
    """A framework-neutral email-auth refusal translated by the HTTP router."""

    def __init__(self, kind: str):
        self.kind = kind
        super().__init__(kind)


@dataclass(frozen=True)
class VerifiedEmail:
    token: str
    email: str
    session_cookie: str


async def start_email_login(email: str, client_ip: str) -> dict:
    """Issue and deliver an email OTP, committing its rate and one-time state atomically."""
    email = _norm_email(email)
    if email.endswith("@" + demo_seed.DEMO_DOMAIN):
        raise EmailAuthError("demo_address")
    if _is_machine_email(email):
        raise EmailAuthError("machine_identity")

    async with database.session_maker() as db:
        await ratestore.sweep(db, OTP_START_NS)
        if not await ratestore.rate_check(
            db, OTP_START_NS,
            [(f"e:{email}", OTP_START_MAX_PER_EMAIL), (f"i:{client_ip}", OTP_START_MAX_PER_IP)],
            OTP_START_WINDOW_S,
        ):
            await db.commit()
            raise EmailAuthError("rate_limited")
        code = f"{_secrets.randbelow(1_000_000):06d}"
        await ratestore.kv_put(
            db, OTP_NS, email,
            {"hash": crypto.hash_token(code), "attempts": MAX_OTP_ATTEMPTS}, EMAIL_CODE_TTL,
        )
        await db.commit()

    result = {"sent": True, "email": email}
    if get_settings().expose_dev_code:
        print(f"[email-otp] {email} -> {code}")
        result["dev_code"] = code
    else:
        await email_sender.send_otp(email, code, ttl_minutes=EMAIL_CODE_TTL // 60)
    return result


async def verify_email_login(email: str, code: str) -> VerifiedEmail:
    """Consume an email OTP and return both CLI and browser credentials for the proven identity."""
    email = _norm_email(email)
    async with database.session_maker() as db:
        entry = await ratestore.kv_get(db, OTP_NS, email)
        if entry is None:
            await db.commit()
            raise EmailAuthError("invalid_code")
        if not hmac.compare_digest(entry["hash"], crypto.hash_token(code.strip())):
            entry["attempts"] -= 1
            if entry["attempts"] <= 0:
                await ratestore.kv_pop(db, OTP_NS, email)
            else:
                await ratestore.kv_put(db, OTP_NS, email, entry, ttl_s=None)
            await db.commit()
            raise EmailAuthError("invalid_code")
        await ratestore.kv_pop(db, OTP_NS, email)
        try:
            user = await signup.find_or_create_user(db, email)
        except signup.MachineIdentityError as exc:
            raise EmailAuthError("machine_identity") from exc
        if user.suspended:
            raise EmailAuthError("suspended")
        await db.commit()
        token = sess.make(user.id, CLI_TOKEN_TTL, user.token_version)
        session_cookie = sess.make(user.id, token_version=user.token_version)
        return VerifiedEmail(token=token, email=user.email, session_cookie=session_cookie)
