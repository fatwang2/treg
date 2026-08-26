"""HTTP cookie helpers shared by authentication routes."""

from fastapi import Request


def _is_https(request: Request) -> bool:
    # behind a reverse proxy (Render), TLS is terminated upstream and forwarded as http + X-Forwarded-Proto.
    return request.headers.get("x-forwarded-proto", "").lower() == "https" or request.url.scheme == "https"


OAUTH_RETURN_COOKIE = "treg_oauth_return"


def _remember_oauth_return(resp, request: Request) -> None:
    """Park where to come back to after the user signs in.

    A RELATIVE path, deliberately — never a full URL. A stored absolute URL would have to be
    validated against our own origin before being redirected to, and getting that check subtly wrong
    is how open redirects happen. A path cannot leave the site.

    Short-lived: this is a detour of seconds, and a stale one would silently hijack the next sign-in.
    """
    target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    resp.set_cookie(OAUTH_RETURN_COOKIE, target, httponly=True, samesite="lax",
                    secure=_is_https(request), max_age=600)


def _take_oauth_return(request: Request) -> str | None:
    """The parked destination, if it is one we actually park — else None.

    Only `/oauth/authorize` is honoured. Accepting any path would turn this cookie into a general
    "redirect me anywhere after login" primitive, which is a phishing aid rather than a feature.
    """
    # Starlette quotes a cookie value containing separators, and not every client strips the quotes
    # back off. Tolerating them here costs nothing; assuming they are absent cost a failing test and
    # would have cost a silently-dropped authorization in production.
    target = (request.cookies.get(OAUTH_RETURN_COOKIE) or "").strip('"')
    return target if target.startswith("/oauth/authorize?") else None
