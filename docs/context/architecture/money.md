---
title: Money — prepaid balance, the ledger, Stripe, and the reports that check it
status: shipped
sources:
  - src/treg/ledger.py
  - src/treg/billing.py
  - src/treg/reconcile.py
related:
  - architecture/catalog.md
  - architecture/proxy-model.md
  - architecture/data-model.md
---

# Money

A catalogued endpoint can be served on **treg's own key** — no provider signup for the caller — which
means treg pays the provider and bills the team. That needs a balance, a way to top it up, and a way
to prove afterwards that the numbers were real. Three modules, one job each:

| Module | Job | May it write money? |
|---|---|---|
| `ledger.py` | the only code path that moves money | **yes — exclusively** |
| `billing.py` | the only code path that talks to Stripe | no (it calls `ledger.topup`) |
| `reconcile.py` | read-only reports that check the ledger against the world | no |

The seam between the first two is one function: `ledger.topup(org, amount_micro, payment_ref)`.
Stripe authorizes a payment on one side, the ledger credits balance on the other, and neither reaches
into the other's job.

## Units: integer micro-USD, everywhere

1 micro = 1e-6 USD. A catalog call costs ~600 micro ($0.0006), so **cents cannot represent one call**
and floats cannot be summed for a year without drifting. The only float is the margin *rate*, turned
into an integer immediately (`with_margin`). Stripe speaks integer **cents**, so 1 cent = 10,000
micro and every crossing goes through `micro_to_cents` / `cents_to_micro` in `billing.py` — the one
file where two unit systems meet. Whole dollars appear only in settings and in what a human types.
Every `*_micro` value has a display-only `*_usd` twin: **never compute against the USD field.**

## The four tables and the invariant

`Org.balance_micro` (materialized) · `CreditBlock` (one funding event, and what is left of it) ·
`Hold` (an open reservation) · `LedgerEntry` (append-only journal).

    balance_micro == sum(block.remaining_micro) - sum(open hold.amount_micro)

The balance is a column rather than a query because `reserve` has to be one conditional UPDATE (see
below). Every operation writes its `LedgerEntry` **in the same transaction, synchronously,
in-request**. Never route a ledger write through `audit.py`: it drops rows past its queue bound and
swallows exceptions, which is right for analytics and fatal for money.

## The five operations (`ledger.py`)

| Op | Effect |
|---|---|
| `grant` | new promotional block, balance up (org creation) |
| `topup` | new purchased block, balance up (after Stripe authorized) |
| `reserve` | balance down by the estimate, `Hold` opened — the hot-path spend gate |
| `settle` | blocks down by the observed cost, hold closed, difference refunded |
| `release` | hold closed, balance refunded in full (upstream failure — not billable) |

**The gate is one statement**, which is the heart of the design:

```sql
UPDATE org SET balance_micro = balance_micro - :est WHERE id = :org AND balance_micro >= :est
```

The WHERE is the check and the SET is the debit, so the *database* decides who gets the last cent.
`rowcount 0` means insufficient funds → `InsufficientBalance` → a 402 the agent can act on. No
SELECT-then-UPDATE, no application lock, same behaviour on SQLite and Postgres: N concurrent callers
against a balance that affords K get exactly K successes.

**Block consumption order** is promotional-first, then oldest-purchased-first. Promo credit is a
marketing expense and never refundable; purchased credit is a deferred-revenue liability and *is*
refundable and disputable — so spending promo first keeps the refundable pool as small as possible
for as long as possible.

**Margin is applied inside the module** (`with_margin`), at reserve AND settle, and the rate in force
is recorded on every entry — so a rate change cannot retroactively rewrite what a call cost, and two
call sites cannot disagree.

**The hold reaper is lazy**, at the top of `reserve`, scoped to the calling org. A crash between relay
and settle would otherwise strand that money forever. A background timer would need a scheduler and
leader election on a multi-instance deploy, and would still only run on a timer; sweeping one org's
stale holds is paid by the caller who benefits from it, and an org that never calls again has no
balance to strand.

**Idempotency on `topup` is enforced by the database.** `stripe_payment_intent` is UNIQUE, and `topup`
FLUSHES immediately after adding the block, before the balance moves: the loser of a race rolls back
and returns the winner's block, giving the same answer as the sequential path. The application-level
SELECT is an optimisation, not the guarantee — two concurrent deliveries of one PaymentIntent both
miss it. (Fixed in #45; the migration is `db.py` A28, placed above the `(B)` legacy block because that
block returns early on a fresh database — precisely the one that needs it.)

## Stripe (`billing.py`)

**Credit happens on the WEBHOOK, never on the browser's return from Checkout.** The success redirect
is a URL the payer controls; treating it as proof of payment would let anyone mint balance by typing
it. The one exception is the off-session auto-top-up charge, where the server itself holds the
PaymentIntent's confirmed status — nothing attacker-supplied is involved — so it credits immediately
and the webhook redelivery lands as a no-op.

The webhook lives at `POST /billing/stripe/webhook`, **deliberately separate from the landing demo's
`/stripe/webhook`** and signed by a different secret: they are different Stripe accounts' events with
different consequences, and sharing a path would let one secret authorize the other's effects. It
**404s when unconfigured**, so a deploy without the secret exposes no unauthenticated POST surface.
`verify_event` uses the SDK's `verify_header` (timestamp tolerance = replay protection, and it handles
the several-signatures case during rotation) rather than `construct_event`, so a genuine event of a
type this SDK version predates is accepted and then ignored, not rejected as forged. A handler failure
returns 500 **on purpose**: that is how Stripe is told to retry.

The Stripe SDK is synchronous, so every call goes through `_sdk()` onto a worker thread — a blocking
network call on the event loop would stall every in-flight request, including the proxy's hot path.

**Auto-top-up is guarded in depth**, because it is the part that can go wrong expensively: recorded
consent (the PSD2/SCA mandate, a compliance requirement rather than a checkbox), a monthly cap, a
cooldown stamped in the DB *before* the charge so a second web worker sees it, a consecutive-failure
limit, and an idempotency key derived from the threshold crossing — so a burst of concurrent calls
that all notice the low balance produces exactly ONE charge.

Authorization: `_billing_org` requires **admin or owner**. A card and a spend policy are the org's
money, not a member's preference.

## The spend ceiling (`api.py`)

`_enforce_platform_daily_cap` is a per-org, per-UTC-day ceiling on platform spend, and it is
**fail-closed** — unlike the per-user call cap, which may let a few extra through under load. A query
that cannot answer refuses the call, because this one meters *our* money. The balance alone is not
enough: auto-top-up refills it, so the cap is the blast radius of both a runaway agent and a pricing
mistake in the catalog.

An endpoint whose price is unknown never reaches this path at all: `catalog_store.platform_eligible`
requires `cost_view(...)["usd"] is not None`, so "we don't know" is refused rather than served free —
see [catalog](catalog.md).

## Checking the work (`reconcile.py`)

Read-only, query-time, no scheduler. Three questions, each needing its own source of truth:

- **`price_drift`** — did the catalog's price stay true? Compares, per endpoint, the estimate
  RESERVED against the cost the provider REPORTED, both on the same `CallRecord` row. Providers
  re-price whenever they like; a silent 10% climb turns a positive margin negative with nothing on
  fire, and this report is the only thing that notices.
- **`provider_spend`** — reads the **ledger**, not the audit table, because it is the number a human
  holds next to an invoice. Audit rows are fire-and-forget and may be missing; ledger rows may not.
- **`repeat_rate`** — measurement only: how much of the bill was the same query twice. Answering it
  first is what makes a cache a decision rather than a guess.

Two aggregations happen in Python rather than SQL on purpose — the ledger's provenance lives in a JSON
`meta` column (portable JSON extraction across SQLite and Postgres is not worth a report), and these
are admin-scale windows over a bounded number of metered calls, the same tradeoff `admin_stats` makes.

## Where a call's money actually moves

    resolve → _platform_offer (priced + eligible?) → _enforce_platform_daily_cap (fail-closed)
            → ledger.reserve (the UPDATE gate; 402 if short)
            → relay upstream
            → settle at the observed cost when the provider reports one
              (dataforseo `cost`, scrapecreators `credits_charged`, akta `credits_consumed` —
              the last is what makes akta's per-section enrich billable: the estimate is an
              upper bound, the settle is the real charge), else at the estimate;
              release instead when the call was not billable

Closing the hold runs on its **own session** (the request's may be mid-rollback from the very error
being released for) and **never raises** — the caller already has their answer, and a ledger hiccup
must not turn a served call into a 500. A hold that fails to close is not lost money either: the
reaper releases it, which errs in the org's favour.
