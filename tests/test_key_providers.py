"""API-key providers (auth_kind="key") — the marketplace's paste-a-key connect flow.

These share Slack's bring-your-own-credential path (verify → store → auto-provision), differing only
in the header or query param the key rides in. The upstream is the shared in-process ASGI app from
conftest (`/whoami` echoes; `/units` and `/units-bad` model Semrush's plain-text balance responses).
"""

from __future__ import annotations

import dataclasses

from httpx import AsyncClient

from treg import oauth_providers as P


# ---- registry shape ----------------------------------------------------------------------
def test_key_providers_are_offerable_without_deployment_credentials():
    """The user brings the key, so treg holds no app of its own — a key provider must be offerable,
    not shown as 'not configured' the way an unset OAuth provider is."""
    for svc in ("apollo", "pdl", "akta", "hunter", "crunchbase", "tikhub", "brightdata", "semrush",
                "justoneapi", "dataforseo", "seranking", "moz", "majestic", "serpstat", "search1api",
                "lusha", "coresignal", "diffbot", "thecompaniesapi", "leadmagic", "fiber-ai",
                "companyenrich", "oceanio", "tomba", "predictleads", "findymail", "branddev",
                "icypeas", "leadsforge", "influencersclub", "crustdata", "aviato",
                "spyfu", "apify", "meta-ad-library", "serpapi",
                "coingecko", "polygon", "finnhub", "twelvedata", "fmp", "eodhd", "marketstack",
                "tiingo"):
        p = P.get(svc)
        assert p is not None, svc
        assert p.auth_kind == "key", svc
        assert p.uses_pasted_secret is True, svc
        assert p.is_token_kind is False, f"{svc}: an API key is not a Slack bot token"
        assert P.is_configured(p) is True, svc
