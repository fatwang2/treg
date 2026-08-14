"""The PUBLIC catalog — the browse pages anyone can read without an account.

The dashboard's Catalog view is behind a session: you have to sign in before you can find out what
treg can call for you, which is the wrong way round for the half of the product that is a public
list of ~2,600 endpoints and their prices. These pages serve that same inventory to anyone (and to
a crawler): every platform, every endpoint, what it does, who serves it and what one call costs.

Server-RENDERED, no JavaScript, no build step. Three reasons, in order:
  1. it has to be readable by a crawler and by an agent that fetches the URL, not just by a browser
     that will run a framework first;
  2. the data behind it is already public (`/catalog/*` needs no auth), so there is nothing to
     fetch client-side that the server cannot simply print;
  3. it renders from `catalog_store` directly — the SAME functions the JSON API answers with — so a
     price or a census can never differ between the page and the API.

What it deliberately does NOT do: sign anyone in, show connection state, or claim treg picks a
provider for you. It compares providers side by side and leaves the choosing to the caller, which
is the same promise the rest of the product makes.

SERVER-SIDE ONLY (it imports `catalog_store`, which pulls pyyaml from the `[server]` extra).
"""

from __future__ import annotations

import html

from . import catalog_store, oauth_providers
from .catalog_store import Catalog

# One shelf per category, in the order a visitor most likely wants them — the same order the
# dashboard's tab bar uses, so the two pages read as one catalog. Anything not named here keeps its
# own name and files after these.
CATEGORY_ORDER = ["SEO/AEO", "Social", "Advertising", "Enrichment", "E-commerce",
                  "Reviews & Apps", "Community", "Developer"]


def esc(s) -> str:
    """Every dynamic value on these pages goes through here. The catalog is curated YAML rather
    than user input, but it is still data being interpolated into markup, and a page that escapes
    only the fields someone remembered to escape is a page waiting for the first summary with an
    ampersand in it."""
    return html.escape("" if s is None else str(s), quote=True)


def _provider_display(service: str) -> str:
    p = oauth_providers.get(service)
    return p.display_name if p else service


def _price_text(cost: dict | None) -> str:
    return catalog_store.cost_label(cost) if cost else ""


# ---- chrome ----------------------------------------------------------------------------------

def _head(title: str, description: str, canonical: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{esc(title)}</title>
<meta name="description" content="{esc(description)}"/>
<link rel="canonical" href="{esc(canonical)}"/>
<meta property="og:title" content="{esc(title)}"/>
<meta property="og:description" content="{esc(description)}"/>
<meta property="og:type" content="website"/>
<meta name="twitter:card" content="summary"/>
<link rel="icon" type="image/svg+xml" href="/favicon.svg"/>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Geist+Pixel&family=Inter:wght@400;450;500;600&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/catalog.css"/>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="topbar">
  <a class="brand" href="/"><span class="glyph">&#9626;</span> treg</a>
  <nav class="toplinks" aria-label="Site">
    <a href="/catalog">Catalog</a>
    <a class="hidem" href="/tutorial">Docs</a>
    <a class="hidem" href="/llms.txt">llms.txt</a>
    <a class="cta" href="/app">Sign in</a>
  </nav>
</header>
<main id="main">"""


_FOOT = """</main>
<footer class="foot">
  <p><b>How a call works.</b> Your agent calls treg, treg injects the provider credential
  server-side and relays the answer verbatim. No provider signup, and no key on your machine.
  Every new team starts with <b>$1.00 of free credit</b>.</p>
  <p class="quiet">treg compares providers of the same capability side by side, with prices. It
  does not route between them or fail over — which provider to call is yours to choose.</p>
  <p class="quiet"><a href="/">Home</a> · <a href="/tutorial">Docs</a> ·
  <a href="/llms.txt">llms.txt</a> · <a href="/terms">Terms</a> · <a href="/privacy">Privacy</a></p>
</footer>
</body>
</html>"""


def _search_form(q: str) -> str:
    """A plain GET form. It works with JavaScript off, it is linkable (`/catalog?q=backlinks`), and
    an agent can construct the URL without reading any of our code."""
    return f"""<form class="find" method="get" action="/catalog" role="search">
  <input type="search" name="q" value="{esc(q)}" placeholder="What do you want to do? e.g. tiktok comments, backlinks, find an email"
         aria-label="Search the catalog"/>
  <button type="submit">Search</button>
</form>"""


def _logo(slug: str, label: str, cls: str = "plogo") -> str:
    """The platform mark, on the same near-white tile the dashboard uses — brand marks are drawn
    for white and half of them vanish otherwise. A slug with no SVG bundled falls back to its
    initial rather than a broken-image icon (`onerror` is markup, not a script)."""
    initial = esc((label or slug or "?")[:1].upper())
    return (f'<span class="{cls}"><img src="/logos/platforms/{esc(slug)}.svg" alt="" aria-hidden="true" '
            f'''onerror="this.replaceWith(document.createTextNode('{initial}'))"/></span>''')


# ---- the index -------------------------------------------------------------------------------

def _platform_card(row: dict) -> str:
    price = row.get("price_from")
    corner = (f'from <b>{esc(catalog_store.cost_label(price))}</b>' if price
              else '<b>free</b> with your own account')
    return f"""<a class="pcard" href="/catalog/p/{esc(row['slug'])}">
  <span class="pcard-top">{_logo(row['slug'], row['label'])}
    <span class="pcard-name"><b>{esc(row['label'])}</b><span class="quiet">{esc(row['category'])}</span></span></span>
  <span class="pcard-sum">{esc(row['summary'])}</span>
  <span class="pcard-foot"><span class="quiet">{row['endpoints']} endpoints</span><span class="price">{corner}</span></span>
</a>"""


def _search_results(q: str, cat: Catalog) -> str:
    """Search over the BROWSE surface only.

    `catalog_store.search` deliberately searches everything, management plumbing included — an
    agent that asks for an endpoint by name should find it even when a shelf hides it. A person
    browsing is asking a different question, and "backlinks" answered with three ways to poll a
    scraper run is an answer to nobody. So the plumbing is filtered out here and the count reports
    what is actually listed. The limit is applied AFTER the filter, or a page of hidden rows would
    silently eat the twenty results worth showing.
    """
    ranked, _total = catalog_store.search(q, cat, limit=600)
    ranked = [(ep, s) for ep, s in ranked if ep["kind"] not in catalog_store.HIDDEN_KINDS]
    total = len(ranked)
    ranked = ranked[:60]
    if not ranked:
        return (f'<p class="empty">Nothing in the catalog matches <b>{esc(q)}</b>. '
                'Try one word fewer, or browse the shelves below.</p>' + _shelves(cat))
    rows = []
    for ep, _score in ranked:
        view = catalog_store.endpoint_view(ep, _provider_display(ep["provider"]), cat)
        ctx = catalog_store.endpoint_context(ep, cat)
        rows.append(f"""<li class="hit">
  <a class="hit-main" href="/catalog/p/{esc(ep['platform'])}#{esc(ep['id'])}">
    <b>{esc(view['name'] or view['summary'])}</b>
    <span class="quiet">{esc(ctx['platform_label'])} · {esc(view['provider_display'])}</span></a>
  <span class="hit-price">{esc(_price_text(view['cost'])) or '&mdash;'}</span>
</li>""")
    more = (f'<p class="quiet">Showing {len(ranked)} of {total} matching endpoints — '
            'narrow the search to see the rest.</p>') if total > len(ranked) else ""
    return (f'<h2 class="shelf-h">{total} endpoint{"" if total == 1 else "s"} match “{esc(q)}”</h2>'
            f'<ul class="hits">{"".join(rows)}</ul>{more}')


def _shelves(cat: Catalog) -> str:
    rows = catalog_store.platform_rows(cat)
    by_cat: dict[str, list[dict]] = {}
    for row in rows:
        by_cat.setdefault(row["category"], []).append(row)
    # Named categories first, in the curated order; anything new the catalog grows keeps its name
    # and files after them alphabetically, rather than disappearing because nobody listed it.
    order = [c for c in CATEGORY_ORDER if c in by_cat] + sorted(c for c in by_cat if c not in CATEGORY_ORDER)
    out = []
    for category in order:
        cards = "".join(_platform_card(r) for r in by_cat[category])
        out.append(f"""<section class="shelf">
  <h2 class="shelf-h">{esc(category)} <span class="count">{len(by_cat[category])}</span></h2>
  <div class="pgrid">{cards}</div>
</section>""")
    return "".join(out)


def index_page(base_url: str, q: str = "") -> str:
    """`/catalog` — every platform treg can call, or the results for `?q=`."""
    cat = catalog_store.load()
    rows = catalog_store.platform_rows(cat)
    n_eps = sum(r["endpoints"] for r in rows)
    n_provs = len({p for r in rows for p in r["providers"]})
    q = (q or "").strip()
    title = (f"“{q}” in the treg catalog" if q
             else f"Catalog — {n_eps:,} tools your agent can call · treg")
    desc = (f"Endpoints matching {q} in the treg catalog, priced per call."
            if q else
            f"Browse {n_eps:,} catalogued endpoints across {len(rows)} platforms and "
            f"{n_provs} providers — what each one does, who serves it, and what one call costs. "
            "No account needed to look.")
    body = _search_results(q, cat) if q else _shelves(cat)
    return f"""{_head(title, desc, base_url + "/catalog")}
<div class="hero">
  <h1>{n_eps:,} tools your agent can call</h1>
  <p class="lead">Every endpoint in the treg catalog, priced per call. treg holds the provider
  account and injects the credential server-side, so your agent can use any of these without
  signing up with anyone — or bring your own key, and those calls are never metered.</p>
  <p class="stats"><b>{n_eps:,}</b> endpoints · <b>{len(rows)}</b> platforms · <b>{n_provs}</b> providers</p>
  {_search_form(q)}
</div>
{body}
{_FOOT}"""


# ---- one platform ----------------------------------------------------------------------------

def _endpoint_row(view: dict) -> str:
    verified = '<span class="tick" title="live-verified against the provider">&check;</span>' if view["verified"] else ""
    docs = (f' <a class="docs" href="{esc(view["docs_url"])}" target="_blank" rel="noopener nofollow">docs</a>'
            if view["docs_url"] else "")
    return f"""<tr id="{esc(view['id'])}">
  <td class="c-what"><b>{esc(view['name'] or view['summary'])}</b>
    <span class="quiet">{esc(view['summary']) if view['name'] else ''}</span></td>
  <td class="c-route"><span class="prov">{esc(view['provider_display'])}</span>
    <code class="route"><span class="m">{esc(view['method'])}</span> {esc(view['path'])}</code>{docs}</td>
  <td class="c-price">{esc(_price_text(view['cost'])) or '&mdash;'}</td>
  <td class="c-v">{verified}</td>
</tr>"""


def _ledger(domains: list[dict]) -> str:
    """The platform's endpoints, filed by subject. A capability several providers implement is ONE
    subject with a row per provider under it — that side-by-side is the comparison the catalog
    exists to make, and it is why the price column is worth reading."""
    out = []
    for section in domains:
        body = []
        for row in section["rows"]:
            if row["kind"] == "merged":
                body.append(f'<tr class="job"><td colspan="4"><b>{esc(row["description"])}</b>'
                            f'<span class="quiet"> — {len(row["endpoints"])} providers do this job</span></td></tr>')
            body += [_endpoint_row(v) for v in row["endpoints"]]
        out.append(f"""<section class="sec">
  <h2 class="shelf-h">{esc(section['domain'])} <span class="count">{len(section['rows'])}</span></h2>
  <div class="tablewrap"><table class="ledger">
    <thead><tr><th class="c-what">What it does</th><th class="c-route">Provider &amp; route</th>
      <th class="c-price">Price</th><th class="c-v" title="live-verified">&check;</th></tr></thead>
    <tbody>{"".join(body)}</tbody>
  </table></div>
</section>""")
    return "".join(out)


def platform_page(slug: str, base_url: str) -> str | None:
    """`/catalog/p/<slug>` — one platform's whole ledger. None when no such platform, so the route
    can answer 404 rather than render an empty page that a crawler would happily index."""
    cat = catalog_store.load()
    eps = [e for e in cat.for_platform(slug) if e["kind"] not in catalog_store.HIDDEN_KINDS]
    if not eps:
        return None
    plat = cat.platforms.get(slug, {})
    label = plat.get("label", slug)
    pairs = [(e, catalog_store.endpoint_view(e, _provider_display(e["provider"]), cat)) for e in eps]
    domains = catalog_store.domain_rows(pairs, cat.capabilities)
    providers = sorted({e["provider"] for e in eps})
    verified = len([e for e in eps if e["verified"]])
    cheapest = min((c for _e, v in pairs if (c := v["cost"]) and c.get("usd")),
                   key=lambda c: c["usd"], default=None)
    price = (f'from <b>{esc(catalog_store.cost_label(cheapest))}</b>' if cheapest
             else '<b>free</b> with your own account')
    # The line that actually runs one of these. The first verified endpoint if there is one — an
    # example nobody has proven against the live API is a bad first impression.
    sample = next((v for _e, v in pairs if v["verified"]), pairs[0][1])
    prov_chips = "".join(
        f'<span class="chip">{esc(_provider_display(p))}</span>' for p in providers)
    title = f"{label} API — {len(eps)} endpoints in the treg catalog"
    desc = (f"{plat.get('summary') or label}. {len(eps)} catalogued endpoints from "
            f"{len(providers)} provider{'' if len(providers) == 1 else 's'}, priced per call, "
            "callable through treg without a provider account.")
    return f"""{_head(title, desc, f"{base_url}/catalog/p/{slug}")}
<p class="crumbs"><a href="/catalog">&larr; Catalog</a> <span class="quiet">/ {esc(plat.get('category', 'Other'))}</span></p>
<div class="hero plat">
  <h1>{_logo(slug, label, "plogo big")} {esc(label)}</h1>
  <p class="lead">{esc(plat.get('summary', ''))}</p>
  <p class="stats"><b>{len(eps)}</b> endpoints · <b>{verified}</b> live-verified · {price}</p>
  <p class="provs"><span class="quiet">Served by</span> {prov_chips}</p>
</div>
<div class="callout">
  <p><b>Call one of these.</b> Point your agent at treg and it runs the line below — treg injects
  the provider key server-side, so nothing lands on your machine.</p>
  <pre class="cmd"><code>{esc(sample['call_template'])}</code></pre>
  <p class="quiet">Prices are per chargeable event and are what the provider charges treg. Where
  several providers do the same job they are listed together, cheapest first — pick one; treg does
  not route between them for you.</p>
</div>
{_ledger(domains)}
{_FOOT}"""
