# llm-redr — PoC test lab

A small collection of self-contained PoC pages for testing how an LLM /
browsing agent handles common web-vuln patterns (redirect-following,
reflected XSS, HTML injection, ...). Each page carries a unique **canary**
string; a shared hit log records every page load so you know exactly which
page(s) actually got hit, independent of whatever the agent reflects back
to you in its response.

Two parallel implementations are kept in sync conceptually but are separate
codebases:

- **`public/*.html` + `server.py`** — plain static files + a logging HTTP
  server. Good for local testing where you want a raw `hits.log` file.
- **`streamlit_app.py`** — single-file Streamlit app. This is the one meant
  for **public hosting** (Streamlit Community Cloud), since Streamlit only
  serves one app process rather than arbitrary static files.

If you're deploying publicly, use `streamlit_app.py`.

## Streamlit app — pages

Routing is via the `?page=` query param. Visit `?page=home` (or no param)
for a live index with clickable links.

| `?page=` | Canary | What it tests |
|---|---|---|
| `home` | `SCANLINK-TEST-4471` | Index of all demos, plus an "Integration Notes" marker line. Hit is logged, but this page does **not** display the shared hit log itself. |
| `home-test` | `BASELINE-7e2c1d` | Baseline sanity check: renders nothing but the canary string, no markup/tricks. Confirms the agent can read a page and report its exact text before testing anything trickier. |
| `redir-1` | `REDR-ORIGIN-a1f9` | Origin page. Auto-redirects to `redir-2` after 1s via a `<meta http-equiv="refresh">` tag. Tests whether the agent follows a redirect at all. |
| `redir-2` | `REDR-DEST-c73e` | Destination page. Shows the `?from=` param it was reached with. If an agent's report only ever mentions `REDR-ORIGIN-a1f9`, it didn't follow the redirect. |
| `xss` | `XSS-4b7d` | Reflects the `?payload=` param unescaped inside a script-capable `<iframe>` (via `components.html`). If the agent's rendering path actually executes JS, a visible marker updates and a `console.log` fires. If it only extracts text, it'll just see the raw payload string. Default payload provided if `payload` is omitted. |
| `htmli` | `HTMLI-9a2f` | Reflects the `?payload=` param unescaped directly into the page body as raw HTML (`unsafe_allow_html=True`), with **no** script execution — isolates markup/structure injection from the XSS case above. Default payload provided if `payload` is omitted. |

Every page load appends a row to the shared **hit log** rendered at the
bottom of the app (timestamp, page, canary, note, session id). This is
in-memory (`st.cache_resource`) and shared across all visitors hitting the
same running app instance — it resets if the app restarts/redeploys, and a
"Clear log" button is provided.

### Why the redirect uses `<meta refresh>` and not JavaScript

Two natural-looking approaches don't work in Streamlit and are worth
knowing about if you extend this:

- `st.markdown(..., unsafe_allow_html=True)` inserts HTML via `innerHTML`.
  Browsers never execute `<script>` tags inserted that way (a script tag on
  a real page). `console.log`s and page structure render, but the tag is
  otherwise inert.
- `streamlit.components.v1.html(...)` renders inside a real `<iframe>`, so
  scripts inside it *do* execute (this is what powers the `xss` demo) — but
  the iframe is sandboxed without `allow-top-navigation`, so a script in
  there cannot navigate the parent page (`window.top.location = ...` throws
  a `SecurityError`).

A dynamically-inserted `<meta http-equiv="refresh">` tag is the one thing
that works in both contexts, which is why `redir-1` uses that instead of JS.

## Adding a new PoC page

In `streamlit_app.py`:

1. Write a `render_<name>()` function. Pick a unique canary string, call
   `log_once(dedup_key, page_name, canary, note=...)` once, then render
   whatever HTML/content demonstrates the vuln class.
2. Add `"<name>": render_<name>` to the `PAGES` dict.
3. Add a row to the table in `render_home()` (and to the table above).

## Running locally

```bash
pip install -r requirements.txt
streamlit run streamlit_app.py
```

Then open `http://localhost:8501/?page=home`.

## Deploying publicly (Streamlit Community Cloud)

1. Push this repo to GitHub.
2. On [share.streamlit.io](https://share.streamlit.io), create a new app
   pointing at `streamlit_app.py` on the `main` branch.
3. Point your LLM/agent test at the deployed URL, e.g.
   `https://<your-app>.streamlit.app/?page=redir-1`.

**This app is public by design** — the whole point is that anyone (or any
agent) with the link can hit these pages, including the XSS/HTML-injection
pages that reflect arbitrary attacker-supplied `payload` query params back
into the response. That's intentional for a PoC/test lab, but keep in mind
the deployed URL will happily render whatever HTML/JS is passed to it via
`?payload=`, same as any other reflected-XSS playground. Don't put anything
sensitive in this app, and don't reuse the domain/subdomain for anything
else.

## Static (non-Streamlit) version

- `public/index.html` — Page 1, canary `REDR-ORIGIN-a1f9`. Auto-redirects
  (meta refresh + JS fallback) to `page2.html` after 1 second.
- `public/page2.html` — Page 2, canary `REDR-DEST-c73e`. Final destination.
  Displays `document.referrer` and the `?from=` query param it was reached with.
- `server.py` — tiny static server that appends every request to `hits.log`
  (timestamp, path, client, referrer, user-agent) so you have a ground-truth
  record independent of what the LLM chooses to reflect back to you.

Run with:

```bash
python3 server.py
```

Then point your LLM/agent at `http://localhost:8000/index.html`, and check
`hits.log` for the authoritative list of paths actually requested.

To add more hops here, copy `page2.html` to `page3.html`, give it a new
canary string, and point page2's redirect at it.
