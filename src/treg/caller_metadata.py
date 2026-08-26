"""Normalize self-reported caller metadata shared by control and execution routes."""

import re

from fastapi import Request


def _norm_client(raw: str) -> str:
    """A runtime name as a short slug. One spelling for both ends of the roster: what an incoming
    header is stored as, and what `promoted_from` must match to hide a detected pair."""
    return re.sub(r"[^a-z0-9-]", "",
                  raw.strip().lower().split("/", 1)[0])[:32]  # "claude-code/1.2" → "claude-code"


def _client_of(request: Request | None) -> str:
    """The calling RUNTIME from X-Treg-Client — attribution, not authentication (anything holding
    the token can claim any name, so this informs the roster and never gates anything). An
    unknown-but-well-formed name is kept, so a new runtime shows up without a release."""
    return _norm_client(request.headers.get("X-Treg-Client", "") if request is not None else "")
