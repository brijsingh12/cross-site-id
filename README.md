# Cross-Site Identity Generator v2

Persistent cross-site user identification **without third-party cookies**.

Works on Safari (Mac + iPhone), Instagram in-app browser, Firefox, and Chrome.

## Architecture

```
Partner Sites                    Identity Server
─────────────                    ───────────────
shop.com ─┐                     ┌─ POST /api/resolve
crow.com  ├─ <script src="…">  ─┤─ GET  /bridge.html  (iframe)
pewpie.com┘                     └─ GET  /bounce        (redirect)
```

### What makes this different

Most implementations rely on a **single mechanism** (usually just fingerprinting or just cookies). This system uses a **4-layer cascading resolution chain** where each layer reinforces the others:

| Layer | Mechanism | Works on Safari? | Survives cookie clear? |
|-------|-----------|-------------------|----------------------|
| 1. Multi-anchor local storage | Cookie + localStorage + IndexedDB + CacheAPI | Yes | Partially (CacheAPI often survives) |
| 2. Server-side fingerprint graph | Tiered hash matching (core → device → full → fuzzy) | Yes | Yes |
| 3. Storage Access API bridge | Hidden iframe + `requestStorageAccess()` | Yes (with prior visit) | No |
| 4. Bounce redirect | First-party cookie on identity domain | Yes | No |

### Fingerprint signals (12 collectors)

- **Canvas** — complex rendering with gradients, shapes, text, bezier curves
- **WebGL** — unmasked renderer/vendor, shader render hash, GPU parameters
- **AudioContext** — offline oscillator + compressor sum
- **Math constants** — 12 transcendental function outputs (engine-specific)
- **Screen geometry** — resolution, color depth, pixel ratio, available area
- **Navigator** — platform, hardware concurrency, touch points, device memory
- **Timezone** — IANA timezone + UTC offset
- **Font detection** — 30+ font probes via canvas width measurement

### Tiered hash matching (server-side)

```
coreHash   = SHA-256(canvas + WebGL renderer + audio)    → O(1) primary lookup
deviceHash = SHA-256(platform + hardware + screen + tz)   → bucket for fuzzy matching
fullHash   = SHA-256(all signals)                         → O(1) secondary lookup
```

Resolution order: `coreHash exact → fullHash exact → localId verify → deviceBucket fuzzy → new user`

Fuzzy matching uses weighted signal comparison (WebGL renderer: 4x, timezone: 3x, etc.) with a 0.72 similarity threshold.

## Files

| File | Purpose |
|------|---------|
| `public/id-generator.js` | Client script — single `<script>` tag on partner sites |
| `public/bridge.html` | Iframe bridge for Storage Access API |
| `server.js` | Express server — identity resolution API |
| `lib/store.js` | Identity graph with tiered indexing + file persistence |

## Quick start

```bash
npm install
npm start
# Server runs on port 3000
```

Then on any partner site:

```html
<script src="https://your-server.com/id-generator.js"></script>
```

Console output: `ID: ntrx_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

## Local testing

```bash
npm start
# Open http://localhost:3000/test-shop.html
# Open http://localhost:3000/test-crow.html
# Open http://localhost:3000/test-pewpie.html
# → All three should show the SAME ID
```

## Programmatic access

```javascript
// Listen for the identification event
window.addEventListener('ntrx:identified', function(e) {
  console.log(e.detail.id); // "ntrx_xxxxxxxx-xxxx-..."
});

// Or read directly (set after resolution)
console.log(window.__ntrx_id);
```

## API endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/id-generator.js` | GET | Client script |
| `/bridge.html` | GET | Iframe bridge (Storage Access API) |
| `/api/resolve` | POST | Identity resolution (fingerprint → ID) |
| `/bounce?r=<url>` | GET | Redirect-based resolution (Safari fallback) |
| `/health` | GET | Server stats |

## Production deployment

1. Deploy to any Node.js host (t3.small, Railway, Fly.io, etc.)
2. Point a domain (e.g., `id.yourcompany.com`) at it
3. Enable HTTPS (required for Secure cookies + CacheAPI)
4. For high-scale: swap `lib/store.js` to use Redis instead of file persistence

## Browser support

| Browser | Status |
|---------|--------|
| Safari (Mac + iPhone) | Fully supported |
| Instagram in-app browser | Fully supported |
| Firefox | Fully supported |
| Chrome | Supported (optional) |
| Brave | Not required / not targeted |
