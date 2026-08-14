"""The PUBLIC catalog pages (`/catalog`, `/catalog/p/<slug>`) — see src/treg/catalogpage.py.

The whole point of these pages is that a stranger with no account can read them, so the tests that
matter are: they answer without a token, they contain the actual inventory (not a shell a script
would have to fill in), and the numbers on them are the same numbers the JSON API reports.
"""

from __future__ import annotations

import re

from httpx import ASGITransport, AsyncClient
import pytest

from treg import catalog_store as cs
from treg.api import app


@pytest.fixture
async def anon():
    """A client carrying NO credential of any kind — the visitor these pages exist for. The shared
    `clients` fixture registers a user and sends its token on every request, which would hide the
    one regression worth catching here: a page that quietly requires a session."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://registry") as c:
        yield c


# ---- the index ------------------------------------------------------------------------------
async def test_catalog_index_is_readable_without_signing_in(anon: AsyncClient):
    r = await anon.get("/catalog")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/html")
    body = r.text
    assert "<title>" in body and "tools your agent can call" in body
    # The inventory is IN the HTML, not fetched by a script the crawler will never run.
    assert "/catalog/p/tiktok" in body
    assert "TikTok" in body


async def test_index_census_matches_the_json_api(anon: AsyncClient):
    """The page and `/catalog/platforms` render from one function (`catalog_store.platform_rows`).
    If someone re-derives either census locally, a visitor reads one endpoint count on the page and
    a different one from the API — the exact drift that sharing the function prevents."""
    rows = (await anon.get("/catalog/platforms")).json()["platforms"]
    total = sum(p["endpoints"] for p in rows)
    page = (await anon.get("/catalog")).text
    assert f"{total:,}" in page
    assert f"<b>{len(rows)}</b> platforms" in page


async def test_index_search_is_a_plain_linkable_get(anon: AsyncClient):
    r = await anon.get("/catalog", params={"q": "tiktok comments"})
    assert r.status_code == 200
    assert "tiktok comments" in r.text
    assert re.search(r"\d+ endpoints? match", r.text), r.text[:400]


async def test_search_hides_the_management_plumbing(anon: AsyncClient):
    """The browse surface only: account/utility endpoints are served by the API but are not what a
    person browsing a catalog is asking for."""
    cat = cs.load()
    hidden = next((e for e in cat.endpoints if e["kind"] in cs.HIDDEN_KINDS), None)
    if hidden is None:
        pytest.skip("this catalog build has no management endpoints")
    page = (await anon.get("/catalog", params={"q": hidden["id"]})).text
    # Its id appears in the echoed query and the title, so look for the RESULT — the deep link a
    # hit would carry (`/catalog/p/<platform>#<id>`).
    assert f'#{hidden["id"]}"' not in page


async def test_a_search_with_no_hits_still_offers_the_shelves(anon: AsyncClient):
    body = (await anon.get("/catalog", params={"q": "zzzz-no-such-tool"})).text
    assert "Nothing in the catalog matches" in body
    assert "/catalog/p/" in body  # a dead end would be the bug


# ---- one platform ---------------------------------------------------------------------------
async def test_platform_page_lists_the_endpoints_with_prices(anon: AsyncClient):
    r = await anon.get("/catalog/p/tiktok")
    assert r.status_code == 200, r.text
    body = r.text
    detail = (await anon.get("/catalog/platforms/tiktok")).json()
    sample = detail["domains"][0]["rows"][0]["endpoints"][0]
    assert sample["path"] in body                       # the route
    assert f'id="{sample["id"]}"' in body               # …anchorable, so a row can be linked to
    assert "treg call" in body                          # …and the line that runs it
    assert cs.cost_label(sample["cost"]) in body        # …and its price


async def test_unknown_platform_is_a_404_not_an_empty_page(anon: AsyncClient):
    """An empty 200 is worse than a 404 here: a crawler indexes it."""
    assert (await anon.get("/catalog/p/not-a-platform")).status_code == 404


async def test_the_page_does_not_promise_routing_it_does_not_do(anon: AsyncClient):
    """treg compares providers; it does not pick one or fail over. A public page is exactly where
    that would get overstated, so the disclaimer is asserted rather than trusted."""
    body = (await anon.get("/catalog/p/tiktok")).text
    assert "does not route between them" in body


async def test_html_is_escaped(anon: AsyncClient):
    """Catalog copy is curated YAML, not user input — but it is still interpolated into markup, and
    an unescaped `&` in one summary is how that stops being true."""
    body = (await anon.get("/catalog")).text
    assert "Reviews &amp; Apps" in body or "&amp;" in body
    assert "<script>" not in body.lower().replace("<script>alert", "")


async def test_the_stylesheet_is_served(anon: AsyncClient):
    r = await anon.get("/catalog.css")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/css")


# ---- the JSON routes must not have been shadowed ----------------------------------------------
async def test_the_html_routes_did_not_swallow_the_json_ones(anon: AsyncClient):
    """`/catalog` (page) and `/catalog/p/<slug>` (page) sit next to `/catalog/platforms`,
    `/catalog/search` and `/catalog/endpoints/<id>` (JSON). Path collisions here would break every
    client silently — the CLI and the dashboard both read the JSON."""
    for path in ("/catalog/platforms", "/catalog/platforms/tiktok", "/catalog/search?q=tiktok"):
        r = await anon.get(path)
        assert r.status_code == 200, path
        assert r.headers["content-type"].startswith("application/json"), path
