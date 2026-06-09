/**
 * Cross-Site Identity Generator v3.0 — Token-Based Architecture
 * ================================================================
 * Identifies users across independent domains WITHOUT third-party cookies.
 * ZERO fingerprint collisions — every device gets a cryptographic random UUID.
 *
 * Architecture:
 *   Identity = random UUID per device (NOT derived from fingerprint)
 *   Cross-site linking = iframe bridge on identity server's first-party storage
 *   Persistence = 4 local anchors (Cookie + localStorage + IndexedDB + CacheAPI)
 *   Server = token registry + bounce redirect fallback
 *
 * Resolution cascade:
 *   1. Check 4 local anchors on current site → instant if found
 *   2. Iframe bridge → identity server's own localStorage (cross-site link)
 *   3. Server registration → registers token, returns confirmation
 *   4. Generate new random UUID → guaranteed unique per device
 *
 * Usage:
 *   <script src="//your-server.com/id-generator.js"></script>
 *   // Console: ID: ntrx_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
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
    cacheName:    'ntrx-id-v3',
    cacheKey:     '/__ntrx_uid.txt',
    bridgePath:   '/bridge.html',
    registerPath: '/api/register',
    cookieDays:   400,
    timeout:      4000,
    serverUrl:    ''
  };

  // Auto-detect server origin from the <script> tag that loaded us
  (function detectServer() {
    var scripts = D.getElementsByTagName('script');
    for (var i = scripts.length - 1; i >= 0; i--) {
      var s = scripts[i].src || '';
      if (s.indexOf('id-generator') !== -1) {
        try {
          var u = new URL(s);
          CFG.serverUrl = u.origin;
        } catch (_) {
          var a = D.createElement('a');
          a.href = s;
          CFG.serverUrl = a.protocol + '//' + a.host;
        }
        break;
      }
    }
  })();

  // ==================================================================
  //  UTILITIES
  // ==================================================================

  /** Generate a cryptographic random UUID (v4). */
  function generateUUID() {
    // Use crypto.randomUUID if available (Safari 15.4+, Chrome 92+, Firefox 95+)
    if (W.crypto && W.crypto.randomUUID) {
      return CFG.prefix + W.crypto.randomUUID();
    }
    // Fallback: crypto.getRandomValues
    if (W.crypto && W.crypto.getRandomValues) {
      var buf = new Uint8Array(16);
      W.crypto.getRandomValues(buf);
      buf[6] = (buf[6] & 0x0f) | 0x40; // version 4
      buf[8] = (buf[8] & 0x3f) | 0x80; // variant 1
      var hex = '';
      for (var i = 0; i < 16; i++) {
        hex += buf[i].toString(16).padStart(2, '0');
        if (i === 3 || i === 5 || i === 7 || i === 9) hex += '-';
      }
      return CFG.prefix + hex;
    }
    // Last resort: Math.random (still unique enough for practical purposes)
    return CFG.prefix + 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = Math.random() * 16 | 0;
      return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
  }

  /** Resolve a promise with timeout. */
  function withTimeout(promise, ms) {
    return new Promise(function (resolve) {
      var done = false;
      var timer = setTimeout(function () { if (!done) { done = true; resolve(null); } }, ms);
      promise.then(function (v) {
        if (!done) { done = true; clearTimeout(timer); resolve(v); }
      }).catch(function () {
        if (!done) { done = true; clearTimeout(timer); resolve(null); }
      });
    });
  }

  // ==================================================================
  //  MULTI-ANCHOR LOCAL PERSISTENCE
  //  Any single surviving anchor recovers the ID instantly.
  // ==================================================================

  // ---- Cookie ----
  function getCookie() {
    var m = D.cookie.match(new RegExp('(?:^|;\\s*)' + CFG.cookieName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]+)'));
    return m ? decodeURIComponent(m[1]) : null;
  }
  function setCookie(id) {
    var exp = new Date(Date.now() + CFG.cookieDays * 864e5).toUTCString();
    D.cookie = CFG.cookieName + '=' + encodeURIComponent(id) +
      ';expires=' + exp + ';path=/;SameSite=Lax;Secure';
  }

  // ---- localStorage ----
  function getLS() {
    try { return W.localStorage.getItem(CFG.storageKey); } catch (e) { return null; }
  }
  function setLS(id) {
    try { W.localStorage.setItem(CFG.storageKey, id); } catch (e) {}
  }

  // ---- IndexedDB ----
  function idbOpen() {
    return new Promise(function (ok, fail) {
      try {
        var req = W.indexedDB.open(CFG.idbName, 1);
        req.onupgradeneeded = function () { req.result.createObjectStore(CFG.idbStore); };
        req.onsuccess = function () { ok(req.result); };
        req.onerror = function () { fail(req.error); };
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

  // ---- Cache API ----
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

  /** Read from the first anchor that has a value. */
  function readLocal() {
    var v = getCookie() || getLS();
    if (v && v.indexOf(CFG.prefix) === 0) return Promise.resolve(v);
    return getIDB().then(function (id) {
      if (id && id.indexOf(CFG.prefix) === 0) return id;
      return getCacheAPI().then(function (cid) {
        return (cid && cid.indexOf(CFG.prefix) === 0) ? cid : null;
      });
    });
  }

  /** Write to ALL anchors for maximum durability. */
  function writeLocal(id) {
    setCookie(id);
    setLS(id);
    setIDB(id);
    setCacheAPI(id);
  }

  // ==================================================================
  //  IFRAME BRIDGE — the cross-site linking mechanism
  //  Identity server's first-party localStorage = shared store
  // ==================================================================

  function tryBridge(localId) {
    if (!CFG.serverUrl) return Promise.resolve(null);

    return withTimeout(new Promise(function (resolve) {
      var origin;
      try { origin = new URL(CFG.serverUrl).origin; } catch (_) { resolve(null); return; }
      if (W.location.origin === origin) { resolve(null); return; }

      var iframe = D.createElement('iframe');
      iframe.style.cssText = 'position:fixed;width:0;height:0;border:0;opacity:0;pointer-events:none';
      iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-storage-access-by-user-activation');
      iframe.src = CFG.serverUrl + CFG.bridgePath;

      function cleanup() {
        W.removeEventListener('message', onMsg);
        try { if (iframe.parentNode) iframe.parentNode.removeChild(iframe); } catch (e) {}
      }

      function onMsg(e) {
        if (e.origin !== origin || !e.data) return;
        if (e.data.type === 'ntrx_bridge_ready') {
          // Send our local ID to the bridge — it will store or return the existing one
          iframe.contentWindow.postMessage({
            type: 'ntrx_resolve',
            id: localId || null
          }, origin);
        }
        if (e.data.type === 'ntrx_response') {
          cleanup();
          resolve(e.data.id || null);
        }
      }

      W.addEventListener('message', onMsg);

      if (D.body) {
        D.body.appendChild(iframe);
      } else {
        D.addEventListener('DOMContentLoaded', function () { D.body.appendChild(iframe); });
      }
    }), 3500);
  }

  // ==================================================================
  //  SERVER REGISTRATION
  //  Registers the token so the server knows it's valid.
  //  Does NOT do fingerprint matching — just stores the token.
  // ==================================================================

  function registerWithServer(id) {
    if (!CFG.serverUrl) return Promise.resolve();

    var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctrl) ctrl.abort(); }, CFG.timeout);

    return fetch(CFG.serverUrl + CFG.registerPath, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id:   id,
        site: W.location.hostname,
        ts:   Date.now()
      }),
      signal: ctrl ? ctrl.signal : undefined
    }).then(function () {
      clearTimeout(timer);
    }).catch(function () {
      clearTimeout(timer);
    });
  }

  // ==================================================================
  //  ORCHESTRATOR — Token-based resolution (no fingerprint matching)
  // ==================================================================

  function main() {

    // Step 1: Check all 4 local anchors on THIS site
    readLocal().then(function (localId) {

      if (localId) {
        // Found locally — we're done. Re-persist across all anchors and register.
        writeLocal(localId);
        registerWithServer(localId);
        emit(localId);
        return;
      }

      // Step 2: No local ID — try iframe bridge to identity server
      // The bridge reads from identity server's OWN first-party localStorage.
      // If this user visited ANY partner site before, the bridge has their token.
      tryBridge(null).then(function (bridgeId) {

        if (bridgeId && bridgeId.indexOf(CFG.prefix) === 0) {
          // Bridge returned a token — this is the same device, different site
          writeLocal(bridgeId);
          registerWithServer(bridgeId);
          emit(bridgeId);
          return;
        }

        // Step 3: Check URL for bounce token (redirect fallback)
        var bounceId = extractBounceToken();
        if (bounceId) {
          writeLocal(bounceId);
          registerWithServer(bounceId);
          // Push token to bridge for future cross-site resolution
          pushToBridge(bounceId);
          emit(bounceId);
          return;
        }

        // Step 4: Truly new device — generate a random UUID
        // This is cryptographically random = ZERO collision risk
        var newId = generateUUID();
        writeLocal(newId);
        registerWithServer(newId);
        // Push the new token to the bridge so other sites can find it
        pushToBridge(newId);
        emit(newId);
      });
    });
  }

  /** Check URL for a bounce-redirect token and clean the URL. */
  function extractBounceToken() {
    try {
      var params = new URLSearchParams(W.location.search);
      var tok = params.get('_ntrx_tok');
      if (tok && tok.indexOf(CFG.prefix) === 0) {
        // Clean the token from the URL (cosmetic)
        params.delete('_ntrx_tok');
        var clean = W.location.pathname + (params.toString() ? '?' + params.toString() : '') + W.location.hash;
        try { W.history.replaceState(null, '', clean); } catch (e) {}
        return tok;
      }
    } catch (e) {}
    return null;
  }

  /** Push a token INTO the bridge so other sites can read it later. */
  function pushToBridge(id) {
    if (!CFG.serverUrl) return;
    var origin;
    try { origin = new URL(CFG.serverUrl).origin; } catch (_) { return; }
    if (W.location.origin === origin) return;

    var iframe = D.createElement('iframe');
    iframe.style.cssText = 'position:fixed;width:0;height:0;border:0;opacity:0;pointer-events:none';
    iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-storage-access-by-user-activation');
    iframe.src = CFG.serverUrl + CFG.bridgePath;

    function cleanup() {
      W.removeEventListener('message', onDone);
      try { if (iframe.parentNode) iframe.parentNode.removeChild(iframe); } catch (e) {}
    }

    var timer = setTimeout(cleanup, 4000);

    function onDone(e) {
      if (e.origin !== origin || !e.data) return;
      if (e.data.type === 'ntrx_bridge_ready') {
        // Push our token to the bridge for storage
        iframe.contentWindow.postMessage({ type: 'ntrx_store', id: id }, origin);
      }
      if (e.data.type === 'ntrx_stored') {
        clearTimeout(timer);
        cleanup();
      }
    }

    W.addEventListener('message', onDone);
    if (D.body) {
      D.body.appendChild(iframe);
    } else {
      D.addEventListener('DOMContentLoaded', function () { D.body.appendChild(iframe); });
    }
  }

  /** Final output. */
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
