/**
 * Cross-Site Identity Generator v4.0 — Safari-First Architecture
 * ================================================================
 * Works on: Safari (Mac/iPhone), Instagram in-app browser, Firefox, Chrome
 *
 * WHY v4:
 *   Safari ITP partitions iframe localStorage per parent-site, making
 *   the iframe bridge useless for cross-site linking. The ONLY reliable
 *   cross-site mechanism on Safari is a bounce redirect through the
 *   identity server (which becomes first-party during the redirect).
 *
 * Resolution cascade:
 *   1. Local anchors (Cookie + localStorage + IndexedDB + CacheAPI)
 *   2. Bounce token in URL (returning from identity server redirect)
 *   3. Iframe bridge (works on Chrome/Firefox, NOT Safari)
 *   4. Auto bounce redirect (Safari/WebKit — the real cross-site link)
 *   5. Generate new UUID (first-ever visit, no prior cross-site token)
 *
 * Safari-specific handling:
 *   - JS-set cookies capped at 7 days by ITP → use all 4 anchors
 *   - localStorage/IndexedDB NOT capped → primary persistence
 *   - Bounce redirect sets server-side HttpOnly cookie (NOT capped by ITP)
 *   - Auto-bounce on first visit ensures server cookie is always set
 */
(function (W, D, N) {
  'use strict';

  // ==================================================================
  //  CONFIGURATION
  // ==================================================================
  var CFG = {
    prefix:       'ntrx_',
    cookieName:   '_ntrx_uid',
    storageKey:   '__ntrx_uid',
    idbName:      'NtrxIdentity',
    idbStore:     'ids',
    cacheName:    'ntrx-id-v4',
    cacheKey:     '/__ntrx_uid.txt',
    bounceFlag:   '_ntrx_did_bounce',
    bridgePath:   '/bridge.html',
    registerPath: '/api/register',
    bouncePath:   '/bounce',
    cookieDays:   400,
    timeout:      4000,
    serverUrl:    ''
  };

  // Auto-detect server origin from our <script> tag
  (function () {
    var scripts = D.getElementsByTagName('script');
    for (var i = scripts.length - 1; i >= 0; i--) {
      var s = scripts[i].src || '';
      if (s.indexOf('id-generator') !== -1) {
        try { CFG.serverUrl = new URL(s).origin; }
        catch (_) {
          var a = D.createElement('a'); a.href = s;
          CFG.serverUrl = a.protocol + '//' + a.host;
        }
        break;
      }
    }
  })();

  // ==================================================================
  //  BROWSER DETECTION
  // ==================================================================

  /** Detect WebKit browsers that partition iframe storage (Safari, Instagram, iOS WebViews). */
  var isWebKit = /AppleWebKit/.test(N.userAgent) && !/Chrome\//.test(N.userAgent) && !/Chromium\//.test(N.userAgent);

  // ==================================================================
  //  UTILITIES
  // ==================================================================

  function generateUUID() {
    if (W.crypto && W.crypto.randomUUID) {
      return CFG.prefix + W.crypto.randomUUID();
    }
    if (W.crypto && W.crypto.getRandomValues) {
      var b = new Uint8Array(16);
      W.crypto.getRandomValues(b);
      b[6] = (b[6] & 0x0f) | 0x40;
      b[8] = (b[8] & 0x3f) | 0x80;
      var h = '';
      for (var i = 0; i < 16; i++) {
        h += b[i].toString(16).padStart(2, '0');
        if (i === 3 || i === 5 || i === 7 || i === 9) h += '-';
      }
      return CFG.prefix + h;
    }
    return CFG.prefix + 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = Math.random() * 16 | 0;
      return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
  }

  function withTimeout(promise, ms) {
    return new Promise(function (resolve) {
      var done = false;
      var t = setTimeout(function () { if (!done) { done = true; resolve(null); } }, ms);
      promise.then(function (v) {
        if (!done) { done = true; clearTimeout(t); resolve(v); }
      }).catch(function () {
        if (!done) { done = true; clearTimeout(t); resolve(null); }
      });
    });
  }

  // ==================================================================
  //  MULTI-ANCHOR LOCAL PERSISTENCE
  // ==================================================================

  function getCookie() {
    var re = new RegExp('(?:^|;\\s*)' + CFG.cookieName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]+)');
    var m = D.cookie.match(re);
    return m ? decodeURIComponent(m[1]) : null;
  }
  function setCookie(id) {
    var exp = new Date(Date.now() + CFG.cookieDays * 864e5).toUTCString();
    D.cookie = CFG.cookieName + '=' + encodeURIComponent(id) +
      ';expires=' + exp + ';path=/;SameSite=Lax;Secure';
  }

  function getLS() {
    try { return W.localStorage.getItem(CFG.storageKey); } catch (e) { return null; }
  }
  function setLS(id) {
    try { W.localStorage.setItem(CFG.storageKey, id); } catch (e) {}
  }

  function idbOpen() {
    return new Promise(function (ok, fail) {
      try {
        var r = W.indexedDB.open(CFG.idbName, 1);
        r.onupgradeneeded = function () { r.result.createObjectStore(CFG.idbStore); };
        r.onsuccess = function () { ok(r.result); };
        r.onerror = function () { fail(r.error); };
      } catch (e) { fail(e); }
    });
  }
  function getIDB() {
    return idbOpen().then(function (db) {
      return new Promise(function (ok) {
        var tx = db.transaction(CFG.idbStore, 'readonly');
        var r = tx.objectStore(CFG.idbStore).get('uid');
        r.onsuccess = function () { ok(r.result || null); };
        r.onerror = function () { ok(null); };
      });
    }).catch(function () { return null; });
  }
  function setIDB(id) {
    return idbOpen().then(function (db) {
      var tx = db.transaction(CFG.idbStore, 'readwrite');
      tx.objectStore(CFG.idbStore).put(id, 'uid');
    }).catch(function () {});
  }

  function getCacheAPI() {
    if (!W.caches) return Promise.resolve(null);
    return W.caches.open(CFG.cacheName).then(function (c) {
      return c.match(new Request(CFG.cacheKey)).then(function (r) {
        return r ? r.text() : null;
      });
    }).catch(function () { return null; });
  }
  function setCacheAPI(id) {
    if (!W.caches) return;
    try {
      W.caches.open(CFG.cacheName).then(function (c) {
        c.put(new Request(CFG.cacheKey), new Response(id, {
          headers: { 'Content-Type': 'text/plain' }
        }));
      }).catch(function () {});
    } catch (e) {}
  }

  function valid(id) {
    return id && typeof id === 'string' && id.indexOf(CFG.prefix) === 0 && id.length > 10;
  }

  function readLocal() {
    var v = getCookie() || getLS();
    if (valid(v)) return Promise.resolve(v);
    return getIDB().then(function (id) {
      if (valid(id)) return id;
      return getCacheAPI().then(function (cid) {
        return valid(cid) ? cid : null;
      });
    });
  }

  function writeLocal(id) {
    setCookie(id);
    setLS(id);
    setIDB(id);
    setCacheAPI(id);
  }

  // ==================================================================
  //  BOUNCE REDIRECT — the Safari cross-site mechanism
  //
  //  Flow:
  //    Partner site → 302 → identity-server.com/bounce → 302 → partner site
  //
  //  During the bounce the identity server is FIRST-PARTY, so it can:
  //    - Read its own HttpOnly cookie (set on a prior bounce)
  //    - Set/refresh that cookie (400-day expiry, NOT capped by ITP)
  //    - Redirect back with the token in the URL
  //
  //  This is the ONLY mechanism that reliably links identity across
  //  sites on Safari, Instagram browser, and iOS WebViews.
  // ==================================================================

  /** Check if we just returned from a bounce (token in URL). */
  function extractBounceToken() {
    try {
      var params = new URLSearchParams(W.location.search);
      var tok = params.get('_ntrx_tok');
      if (valid(tok)) {
        // Clean token from URL so user doesn't see it
        params.delete('_ntrx_tok');
        var clean = W.location.pathname +
          (params.toString() ? '?' + params.toString() : '') +
          W.location.hash;
        try { W.history.replaceState(null, '', clean); } catch (e) {}
        // Mark that we've bounced (prevents re-bounce loops)
        try { W.sessionStorage.setItem(CFG.bounceFlag, '1'); } catch (e) {}
        return tok;
      }
    } catch (e) {}
    return null;
  }

  /** Initiate a bounce redirect to the identity server. */
  function doBounce() {
    if (!CFG.serverUrl) return false;

    // Prevent infinite loops — only bounce once per session
    try {
      if (W.sessionStorage.getItem(CFG.bounceFlag)) return false;
      W.sessionStorage.setItem(CFG.bounceFlag, '1');
    } catch (e) {}

    var returnUrl = W.location.href;
    // Strip any existing _ntrx_tok from the return URL
    try {
      var u = new URL(returnUrl);
      u.searchParams.delete('_ntrx_tok');
      returnUrl = u.toString();
    } catch (e) {}

    W.location.replace(
      CFG.serverUrl + CFG.bouncePath +
      '?r=' + encodeURIComponent(returnUrl)
    );
    return true; // navigation started
  }

  // ==================================================================
  //  IFRAME BRIDGE — works on Chrome/Firefox (NOT Safari)
  // ==================================================================

  function tryBridge(localId) {
    // Skip bridge entirely on WebKit — it's partitioned and useless
    if (isWebKit) return Promise.resolve(null);
    if (!CFG.serverUrl) return Promise.resolve(null);

    return withTimeout(new Promise(function (resolve) {
      var origin;
      try { origin = new URL(CFG.serverUrl).origin; } catch (_) { resolve(null); return; }
      if (W.location.origin === origin) { resolve(null); return; }

      var iframe = D.createElement('iframe');
      iframe.style.cssText = 'position:fixed;width:0;height:0;border:0;opacity:0;pointer-events:none';
      iframe.src = CFG.serverUrl + CFG.bridgePath;

      function cleanup() {
        W.removeEventListener('message', onMsg);
        try { if (iframe.parentNode) iframe.parentNode.removeChild(iframe); } catch (e) {}
      }

      function onMsg(e) {
        if (e.origin !== origin || !e.data) return;
        if (e.data.type === 'ntrx_bridge_ready') {
          iframe.contentWindow.postMessage({ type: 'ntrx_resolve', id: localId || null }, origin);
        }
        if (e.data.type === 'ntrx_response') {
          cleanup();
          resolve(e.data.id || null);
        }
      }

      W.addEventListener('message', onMsg);
      if (D.body) D.body.appendChild(iframe);
      else D.addEventListener('DOMContentLoaded', function () { D.body.appendChild(iframe); });
    }), 3500);
  }

  /** Push token to bridge for Chrome/Firefox cross-site use. */
  function pushToBridge(id) {
    if (isWebKit || !CFG.serverUrl) return;
    var origin;
    try { origin = new URL(CFG.serverUrl).origin; } catch (_) { return; }
    if (W.location.origin === origin) return;

    var iframe = D.createElement('iframe');
    iframe.style.cssText = 'position:fixed;width:0;height:0;border:0;opacity:0;pointer-events:none';
    iframe.src = CFG.serverUrl + CFG.bridgePath;

    function cleanup() {
      W.removeEventListener('message', onDone);
      try { if (iframe.parentNode) iframe.parentNode.removeChild(iframe); } catch (e) {}
    }
    var timer = setTimeout(cleanup, 4000);
    function onDone(e) {
      if (e.origin !== origin || !e.data) return;
      if (e.data.type === 'ntrx_bridge_ready') {
        iframe.contentWindow.postMessage({ type: 'ntrx_store', id: id }, origin);
      }
      if (e.data.type === 'ntrx_stored') { clearTimeout(timer); cleanup(); }
    }
    W.addEventListener('message', onDone);
    if (D.body) D.body.appendChild(iframe);
    else D.addEventListener('DOMContentLoaded', function () { D.body.appendChild(iframe); });
  }

  // ==================================================================
  //  SERVER REGISTRATION (fire-and-forget analytics)
  // ==================================================================

  function registerWithServer(id) {
    if (!CFG.serverUrl) return;
    try {
      var body = JSON.stringify({ id: id, site: W.location.hostname, ts: Date.now() });
      // Use sendBeacon if available (doesn't block navigation)
      if (N.sendBeacon) {
        N.sendBeacon(CFG.serverUrl + CFG.registerPath, new Blob([body], { type: 'application/json' }));
      } else {
        fetch(CFG.serverUrl + CFG.registerPath, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: body,
          keepalive: true
        }).catch(function () {});
      }
    } catch (e) {}
  }

  // ==================================================================
  //  ORCHESTRATOR
  // ==================================================================

  function main() {

    // ── Step 1: check if we just returned from a bounce redirect ──
    var bounceId = extractBounceToken();
    if (bounceId) {
      writeLocal(bounceId);
      registerWithServer(bounceId);
      pushToBridge(bounceId);
      emit(bounceId);
      return;
    }

    // ── Step 2: check all 4 local anchors ──
    readLocal().then(function (localId) {

      if (localId) {
        writeLocal(localId); // refresh all anchors
        registerWithServer(localId);
        emit(localId);
        return;
      }

      // ── Step 3: try iframe bridge (Chrome/Firefox only) ──
      tryBridge(null).then(function (bridgeId) {

        if (valid(bridgeId)) {
          writeLocal(bridgeId);
          registerWithServer(bridgeId);
          emit(bridgeId);
          return;
        }

        // ── Step 4: auto bounce redirect (Safari/WebKit) ──
        //  Navigates to identity server → server reads its HttpOnly cookie
        //  → redirects back with token in URL → step 1 catches it on reload
        if (isWebKit) {
          var bounced = doBounce();
          if (bounced) return; // page is navigating away
        }

        // ── Step 5: generate new UUID (truly new device) ──
        var newId = generateUUID();
        writeLocal(newId);
        registerWithServer(newId);
        pushToBridge(newId);

        // On WebKit: also do a bounce to register this new token on the
        // identity server's cookie, so future cross-site visits find it.
        // We already have the ID locally, so this is a background operation.
        if (isWebKit && CFG.serverUrl) {
          // Use a hidden image to trigger the bounce without navigating away.
          // The server will set its HttpOnly cookie when it sees this request.
          var img = new Image();
          img.src = CFG.serverUrl + '/bounce-set?t=' + encodeURIComponent(newId);
        }

        emit(newId);
      });
    });
  }

  function emit(id) {
    console.log('ID: ' + id);
    W.__ntrx_id = id;
    try {
      W.dispatchEvent(new CustomEvent('ntrx:identified', { detail: { id: id } }));
    } catch (e) {}
  }

  // ==================================================================
  //  BOOTSTRAP
  // ==================================================================
  if (D.readyState === 'loading') {
    D.addEventListener('DOMContentLoaded', main);
  } else {
    setTimeout(main, 0);
  }

})(window, document, navigator);
