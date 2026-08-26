"""Identity provisioning and first-team creation use cases."""

import logging
from urllib.parse import unquote

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from .. import adsconv, health, ledger, referrals, sandbox as demo_sandbox
from ..db import session_maker
from ..domain.governance.teams import _make_org_membership, _slugify
from ..domain.identity.access import _is_machine_email, _norm_email
from ..models import Org, User
from ..timeutil import utcnow_naive as _utcnow_naive


class SignupError(Exception):
    """A framework-neutral signup refusal translated by the HTTP router."""

    def __init__(self, kind: str):
        self.kind = kind
        super().__init__(kind)


class MachineIdentityError(Exception):
    """A machine identity reached a human identity-provisioning command."""


async def find_or_create_user(db: AsyncSession, email: str) -> User:
    """Find a user by email, else register them — the user ONLY, **no auto personal org**. The shared
    core of every identity door (GitHub / Google / email OTP). A brand-new user therefore lands with
    zero teams and is asked to NAME + CREATE their first team (the dashboard's mandatory welcome, or
    `treg org create`) — we never spawn a throwaway personal org they didn't ask for. Their identity
    token is user-scoped, so it works before they have any org (org chosen per-request via X-Treg-Org).
    Caller commits."""
    email = _norm_email(email)
    # Machine identities (agents, the published demo token) are minted by an admin and act ONLY by
    # their token. This is the single choke point every identity door shares, so blocking here means
    # no door — GitHub, Google, email OTP, invite sign-in — can hand a human an agent's identity.
    # (The domains are unroutable, so a code could never be delivered anyway; this makes it explicit.)
    if _is_machine_email(email):
        raise MachineIdentityError
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user is None:
        user = User(email=email)
        db.add(user)
        try:
            await db.flush()  # surfaces the unique-email violation on a concurrent first-login race
        except IntegrityError:
            await db.rollback()  # another worker just created this same new user — reuse theirs
            return (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    return user


async def _grant_signup_promo(db: AsyncSession, org: Org) -> None:
    """Give a BRAND-NEW org its promotional balance, so an agent's first call needs no key and no card
    (`settings.promo_grant_micro`, $1 by default). Called after the org is committed, from every door
    that creates a real team — `ledger.grant` is idempotent per (org, kind), so a retried signup or a
    second door can't double-grant, and existing orgs are never backfilled.

    Demo/sandbox teams are created elsewhere (demo.py / sandbox.py) and deliberately get nothing: a
    published demo token must not be able to spend real money. A grant failure must not fail the
    signup — the org exists, and it can be topped up — so it is logged, not raised.
    """
    if org is None or org.id is None or org.demo or org.public_demo:
        return
    try:
        # Queue BEFORE granting: adsconv.queue() only adds a row inside a SAVEPOINT, it never commits.
        # ledger.grant() commits internally, so calling it second is what makes its commit durable for
        # BOTH rows in one transaction — the event and its conversion must land together (see
        # adsconv.queue's docstring). Reordering this silently reintroduces a two-transaction gap.
        # Same door, same once-only guarantee: this function is already the single place a brand-new
        # real team comes into existence.
        try:
            await adsconv.queue(db, org, adsconv.ACTION_SIGNUP)
        except Exception as exc:  # noqa: BLE001 — its OWN guard, deliberately, not the outer one
            # Because the queue now runs FIRST, sharing the outer except would mean an unexpected
            # failure here (anything but the IntegrityError queue() already absorbs) skips the grant
            # entirely and costs the team its $1 promotional credit. A marketing metric must not be
            # able to take away a product benefit: swallow it here so the grant still runs.
            logging.getLogger("treg").warning("ad conversion queue failed for org %s: %s", org.id, exc)
        await ledger.grant(db, org.id)  # commits — absorbs the queued conversion row too
    except Exception as exc:  # noqa: BLE001 — the team is already created; don't 500 the signup over credit
        logging.getLogger("treg").warning("promo grant failed for org %s: %s", org.id, exc)


def _ad_attribution_from(raw_cookie: str) -> tuple[str, str, str]:
    """Return (click-id field, click-id, landing), with legacy GCLID-cookie compatibility."""
    if not adsconv.enabled():
        return "", "", ""
    if not raw_cookie:
        return "", "", ""
    first, separator, rest = unquote(raw_cookie).partition("|")
    if separator and first in ("gclid", "gbraid", "wbraid"):
        click_id, _, landing = rest.partition("|")
        click_field = first
    else:
        # Old cookies were `CLICK_ID|landing` and always held a GCLID.
        click_field, click_id, landing = "gclid", first, rest
    return click_field, click_id.strip()[:255], landing.strip()[:64]


_UTM_FIELDS = ("utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_referrer")


def _utm_attribution_from(raw_cookie: str) -> dict[str, str]:
    """First-touch traffic source from the `treg_utm` cookie (set by web/sitetrack.js):
    `source|medium|campaign|term|content|referring-host`, URL-encoded. Missing/short cookies yield
    fewer fields; anything unparseable yields nothing. Values are capped so a hostile cookie cannot
    bloat the row."""
    if not raw_cookie:
        return {}
    parts = [part.strip()[:100] for part in unquote(raw_cookie).split("|")]
    return {key: value for key, value in zip(_UTM_FIELDS, parts) if value}


def _stamp_utm(org: Org, raw_cookie: str) -> None:
    """Persist the first-touch source on a brand-new team. Independent of the Google-Ads `treg_ad`
    path: a sponsor link or a newsletter has no click id, and this is what lets us count its
    signups. Called from both signup doors, like `_ad_attribution_from`."""
    for key, value in _utm_attribution_from(raw_cookie).items():
        setattr(org, key, value)


async def _redeem_referral(
    db: AsyncSession, raw_cookie: str, user: User, org: Org,
) -> None:
    """Attribute a brand-new team to whoever's link brought them here. Owes nothing yet; the bonus
    is earned at the team's first paid top-up, not at signup (see referrals.py).

    Team creation is the right and only redemption point: `find_or_create_user` deliberately makes
    no org, so this is where a person first becomes a tenant with a balance. It fires on every team
    a user creates, and `referrals.attribute` refuses self-referrals, demo teams, unknown codes, and
    orgs that already carry a referral.

    A referral is a marketing nicety and a signup is not. Nothing here may ever be the reason
    someone cannot make a team.
    """
    try:
        code = referrals.normalize_code((raw_cookie or "").strip('"'))
        if code:
            await referrals.attribute(db, user=user, org=org, code=code)
    except Exception as exc:  # noqa: BLE001
        logging.getLogger("treg").warning("referral attribution failed for org %s: %s", org.id, exc)


async def register_user(
    *, email: str, webhook_url: str | None, ad_cookie: str, utm_cookie: str, referral_cookie: str,
) -> dict:
    async with session_maker() as db:
        email = _norm_email(email)
        # Open registration predates find_or_create_user, so it needs the same machine-domain block;
        # otherwise a caller could squat an agent address before an admin mints that agent.
        if _is_machine_email(email):
            raise SignupError("machine_identity")
        if webhook_url and not health.safe_webhook_url(webhook_url):  # SSRF guard on the alert URL
            raise SignupError("unsafe_webhook")
        if (await db.execute(select(User).where(User.email == email))).scalar_one_or_none():
            raise SignupError("email_exists")
        user = User(email=email)
        db.add(user)
        await db.flush()
        org, token = await _make_org_membership(
            db, user, name=email, slug_base=_slugify(email), role="owner", webhook_url=webhook_url,
        )
        click_field, gclid, landing = _ad_attribution_from(ad_cookie)
        if gclid:
            org.ad_gclid = gclid
            org.ad_click_id_type = click_field
            org.ad_landing = landing or None
            # asyncpg rejects aware datetimes for this TIMESTAMP WITHOUT TIME ZONE column.
            org.ad_click_at = _utcnow_naive()
            db.add(org)
        _stamp_utm(org, utm_cookie)
        db.add(org)
        try:
            await db.commit()
        except IntegrityError as exc:
            raise SignupError("email_exists") from exc
        await _grant_signup_promo(db, org)
        # Both org-creating doors redeem because both end with a person owning a fresh team.
        await _redeem_referral(db, referral_cookie, user, org)
        return {
            "id": user.id,
            "email": user.email,
            "org": org.slug,
            "org_id": org.id,
            "role": "owner",
            "token": token,
        }


async def create_org(
    *, user: User, name: str, ad_cookie: str, utm_cookie: str, referral_cookie: str,
) -> dict:
    async with session_maker() as db:
        if demo_sandbox.is_sandbox_user(user):  # anonymous sandbox visitors cannot mint real teams
            raise SignupError("sandbox_user")
        click_field, gclid, landing = _ad_attribution_from(ad_cookie)
        # A browser sign-in reaches this door instead of /users, so both doors must read attribution.
        for _ in range(3):  # a concurrent create can claim the slug before commit; retry a fresh lookup
            org, token = await _make_org_membership(
                db, user, name=name, slug_base=_slugify(name), role="owner",
            )
            if gclid:
                org.ad_gclid = gclid
                org.ad_click_id_type = click_field
                org.ad_landing = landing or None
                # asyncpg rejects aware datetimes for this TIMESTAMP WITHOUT TIME ZONE column.
                org.ad_click_at = _utcnow_naive()
                db.add(org)
            _stamp_utm(org, utm_cookie)
            db.add(org)
            try:
                await db.commit()
                break
            except IntegrityError:
                await db.rollback()
        else:
            raise SignupError("slug_conflict")
        await _grant_signup_promo(db, org)
        await _redeem_referral(db, referral_cookie, user, org)
        return {
            "org": org.slug,
            "org_id": org.id,
            "name": org.name,
            "role": "owner",
            "token": token,
        }
