"""Team signup and governance HTTP routes."""

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ..application import signup as signup_use_cases
from ..db import get_session
from ..domain.governance import teams
from ..domain.identity.access import require_identity
from ..models import User
from .signup_cookies import REFERRAL_COOKIE


class UserIn(BaseModel):
    email: str
    webhook_url: str | None = None


class OrgIn(BaseModel):
    name: str


_SIGNUP_HTTP_ERRORS = {
    "machine_identity": (403, "this address cannot be used to sign in"),
    "unsafe_webhook": (422, "webhook_url must be a public http(s) URL"),
    "email_exists": (409, "email already registered"),
    "sandbox_user": (403, (
        "the demo sandbox can't create a real team — sign in with GitHub, Google, or email to make one"
    )),
    "slug_conflict": (409, "could not allocate a unique org slug — retry"),
}


def _signup_http_error(exc: signup_use_cases.SignupError) -> HTTPException:
    status_code, detail = _SIGNUP_HTTP_ERRORS[exc.kind]
    return HTTPException(status_code=status_code, detail=detail)


# The app alias preserves the handlers' @app decorators and the ordered attachment convention.
app = APIRouter()
signup_router = app


@app.post("/users")
async def register_user(body: UserIn, request: Request) -> dict:
    try:
        return await signup_use_cases.register_user(
            email=body.email,
            webhook_url=body.webhook_url,
            ad_cookie=request.cookies.get("treg_ad") or "",
            utm_cookie=request.cookies.get("treg_utm") or "",
            referral_cookie=request.cookies.get(REFERRAL_COOKIE) or "",
        )
    except signup_use_cases.SignupError as exc:
        raise _signup_http_error(exc) from exc


@app.post("/orgs")
async def create_org(
    body: OrgIn, request: Request,
    user: User = Depends(require_identity),
) -> dict:
    try:
        return await signup_use_cases.create_org(
            user=user,
            name=body.name,
            ad_cookie=request.cookies.get("treg_ad") or "",
            utm_cookie=request.cookies.get("treg_utm") or "",
            referral_cookie=request.cookies.get(REFERRAL_COOKIE) or "",
        )
    except signup_use_cases.SignupError as exc:
        raise _signup_http_error(exc) from exc


app = APIRouter()
org_entry_router = app


@app.get("/orgs")
async def list_orgs(
    user: User = Depends(require_identity),
    x_treg_token: str = Header(default=""),
    x_treg_org: str = Header(default=""),
    db: AsyncSession = Depends(get_session),
) -> list[dict]:
    return await teams.list_user_orgs(
        user_id=user.id,
        x_treg_token=x_treg_token,
        x_treg_org=x_treg_org,
        db=db,
    )
