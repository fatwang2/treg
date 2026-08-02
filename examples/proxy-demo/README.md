# treg proxy demo

A tiny web app that calls a real API it has **no key for**. Click a button, see who answers.

The point of the demo is that the code does not change between the two runs. `server.js` never mentions
treg, never reads a secret, and has no dependencies. The credential appears only because treg is the
parent process.

## Run it

```bash
node server.js          # plain: the call goes out as-is
treg node server.js     # the same code, credentialed by your team
```

Open <http://localhost:3000> and click **Call api.openai.com**.

| Run | What OpenAI answers |
|---|---|
| `node server.js` | `401 — Missing bearer authentication in header`. No key, no call. |
| `treg node server.js` | `200` and the real model list. treg injected your team's key **on the server**. |

The second button calls `example.com`, which is not a registered tool. It returns `200` either way: an
address treg does not know is tunnelled without being read. That is the other half of the promise.

Requires the `api.openai.com` tool to be registered in your active team (`treg tool ls`). Any registered
host works — edit `TARGETS` at the top of `server.js`.

## One honest wrinkle: Node and proxies

Node's built-in `fetch` **ignores** `HTTPS_PROXY` until **Node 24**, where `NODE_USE_ENV_PROXY=1` (which
treg sets) turns it on. On Node 23 or older, a plain `fetch()` walks straight past the proxy and you get
the same `401` under treg as without it.

So this demo speaks to the proxy explicitly — `CONNECT`, then TLS over the tunnel — in
`throughProxy()`. About 30 lines, written out only so the demo runs on any Node version.

**Real apps do not need that.** Every common HTTP client already reads the environment: `axios`, `got`,
`undici`'s `ProxyAgent`, python-`requests`, `httpx`, `curl`, `git`. On Node 24+, so does `fetch`. Check
with:

```bash
node --version          # 24 or newer → plain fetch() is captured
```
