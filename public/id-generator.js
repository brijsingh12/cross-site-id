/**
 * Cross-Site Identity Generator v2.0
 * ------------------------------------
 * Identifies users across independent domains WITHOUT third-party cookies.
 *
 * Strategy layers (cascading):
 *   1. Multi-anchor local persistence (Cookie + localStorage + IndexedDB + CacheAPI)
 *   2. Server-side tiered fingerprint matching (core / device / full hashes)
 *   3. Storage Access API via hidden iframe bridge (Safari)
 *   4. Client-side fingerprint fallback
 *
 * Fingerprint signals (ordered by stability):
 *   Canvas rendering | WebGL renderer/vendor/render | AudioContext
 *   Math constants   | Screen geometry              | Navigator props
 *   Timezone         | Font detection               | WebGL params
 *
 * Usage:
 *   <script src="//your-server.com/id-generator.js"></script>
 *   // Console: ID: ntrx_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
 *   // window.__ntrx_id also set
 *   // CustomEvent 'ntrx:identified' dispatched on window
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
    cacheName:    'ntrx-id-v2',
    cacheKey:     '/__ntrx_uid.txt',
    bridgePath:   '/bridge.html',
    resolvePath:  '/api/resolve',
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

  function hex(buf) {
    for (var h = '', v = new Uint8Array(buf), i = 0; i < v.length; i++)
      h += v[i].toString(16).padStart(2, '0');
    return h;
  }

  function sha256(str) {
    if (W.crypto && W.crypto.subtle) {
      return W.crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)).then(hex);
    }
    // Fallback: dual djb2 producing 64-hex-char string
    for (var a = 5381, b = 52711, i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      a = ((a << 5) + a + c) >>> 0;
      b = ((b << 5) + b + c) >>> 0;
    }
    var s = a.toString(16) + b.toString(16);
    while (s.length < 64) s += ((a * b + s.length) >>> 0).toString(16);
    return Promise.resolve(s.slice(0, 64));
  }

  /** Deterministic JSON for any nested object (sorted keys). */
  function stableJSON(v) {
    if (v === null || v === undefined) return 'null';
    if (typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return '[' + v.map(stableJSON).join(',') + ']';
    return '{' + Object.keys(v).sort().map(function (k) {
      return '"' + k + '":' + stableJSON(v[k]);
    }).join(',') + '}';
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
  //  FINGERPRINT COLLECTORS
  // ==================================================================

  /** Canvas — complex rendering to maximize cross-GPU/font entropy. */
  function fpCanvas() {
    try {
      var c = D.createElement('canvas');
      c.width = 300; c.height = 80;
      var x = c.getContext('2d');
      if (!x) return '';

      // Background gradient
      var lg = x.createLinearGradient(0, 0, 300, 0);
      lg.addColorStop(0, '#ff6b6b');
      lg.addColorStop(0.5, '#4ecdc4');
      lg.addColorStop(1, '#45b7d1');
      x.fillStyle = lg;
      x.fillRect(0, 0, 300, 80);

      // Overlapping semi-transparent shapes
      x.globalAlpha = 0.7;
      x.fillStyle = '#e74c3c';
      x.beginPath(); x.arc(55, 35, 28, 0, Math.PI * 2); x.fill();
      x.fillStyle = '#3498db';
      x.beginPath(); x.arc(95, 35, 28, 0, Math.PI * 2); x.fill();
      x.globalAlpha = 1;

      // Bezier curve (sub-pixel anti-aliasing)
      x.strokeStyle = '#6c5ce7'; x.lineWidth = 2.5;
      x.beginPath();
      x.moveTo(0, 60);
      x.bezierCurveTo(75, 10, 225, 70, 300, 20);
      x.stroke();

      // Pangram text — exercises many glyphs
      x.fillStyle = '#2d3436';
      x.font = 'bold 17px Arial, sans-serif';
      x.fillText('Cwm fjord veg balks nth pyx quiz', 6, 28);

      x.fillStyle = '#636e72';
      x.font = 'italic 13px "Georgia", serif';
      x.fillText('\u00c0\u00e7\u00fc\u00f1 0123456789', 6, 72);

      // Shadow
      x.shadowColor = '#000';
      x.shadowBlur = 4;
      x.fillStyle = '#f1c40f';
      x.font = '11px monospace';
      x.fillText('\u263a\u2602\u2660', 260, 72);

      return c.toDataURL();
    } catch (e) { return ''; }
  }

  /** WebGL — hardware renderer string + shader render hash. */
  function fpWebGL() {
    try {
      var c = D.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return null;

      var dbg = gl.getExtension('WEBGL_debug_renderer_info');
      var info = {
        vendor:   dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
        renderer: dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
        version:  gl.getParameter(gl.VERSION),
        slVer:    gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        maxTex:   gl.getParameter(gl.MAX_TEXTURE_SIZE),
        maxVP:    Array.from(gl.getParameter(gl.MAX_VIEWPORT_DIMS) || []),
        maxAniso: (function () {
          var ext = gl.getExtension('EXT_texture_filter_anisotropic') ||
                    gl.getExtension('WEBKIT_EXT_texture_filter_anisotropic');
          return ext ? gl.getParameter(ext.MAX_TEXTURE_MAX_ANISOTROPY_EXT) : 0;
        })(),
        aliasedLineW: Array.from(gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE) || []),
        aliasedPtSz:  Array.from(gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE) || []),
        maxFragUni:   gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS),
        maxVertUni:   gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS),
        exts:         (gl.getSupportedExtensions() || []).sort().join(',')
      };

      // Render a coloured triangle and hash pixel output
      c.width = 64; c.height = 64;
      var vs = 'attribute vec2 p;void main(){gl_Position=vec4(p,0,1);}';
      var fs = 'precision mediump float;void main(){gl_FragColor=vec4(0.867,0.271,0.224,1.0);}';
      function mkShader(src, t) {
        var s = gl.createShader(t);
        gl.shaderSource(s, src);
        gl.compileShader(s);
        return s;
      }
      var prog = gl.createProgram();
      gl.attachShader(prog, mkShader(vs, gl.VERTEX_SHADER));
      gl.attachShader(prog, mkShader(fs, gl.FRAGMENT_SHADER));
      gl.linkProgram(prog);
      gl.useProgram(prog);
      var buf = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, buf);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-0.8, -0.8, 0.8, -0.8, 0, 0.8]), gl.STATIC_DRAW);
      var loc = gl.getAttribLocation(prog, 'p');
      gl.enableVertexAttribArray(loc);
      gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
      gl.clearColor(0, 0, 0, 1);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      var px = new Uint8Array(64 * 64 * 4);
      gl.readPixels(0, 0, 64, 64, gl.RGBA, gl.UNSIGNED_BYTE, px);
      for (var h = 0, j = 0; j < px.length; j += 37)
        h = ((h << 5) - h + px[j]) | 0;
      info.renderHash = h;

      return info;
    } catch (e) { return null; }
  }

  /** AudioContext — offline oscillator + compressor produces device-specific sum. */
  function fpAudio() {
    return new Promise(function (resolve) {
      try {
        var AC = W.OfflineAudioContext || W.webkitOfflineAudioContext;
        if (!AC) { resolve(''); return; }

        var ctx = new AC(1, 5000, 44100);
        var osc = ctx.createOscillator();
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(10000, ctx.currentTime);

        var comp = ctx.createDynamicsCompressor();
        comp.threshold.setValueAtTime(-50, ctx.currentTime);
        comp.knee.setValueAtTime(40, ctx.currentTime);
        comp.ratio.setValueAtTime(12, ctx.currentTime);
        comp.attack.setValueAtTime(0, ctx.currentTime);
        comp.release.setValueAtTime(0.25, ctx.currentTime);

        osc.connect(comp);
        comp.connect(ctx.destination);
        osc.start(0);

        var settled = false;
        ctx.startRendering().then(function (buf) {
          if (settled) return;
          settled = true;
          var d = buf.getChannelData(0);
          var sum = 0;
          for (var i = 4500; i < 5000; i++) sum += Math.abs(d[i]);
          resolve(sum.toFixed(8));
        }).catch(function () { if (!settled) { settled = true; resolve(''); } });

        // Safety timeout
        setTimeout(function () { if (!settled) { settled = true; resolve(''); } }, 2000);
      } catch (e) { resolve(''); }
    });
  }

  /** Math constants — tiny differences across JS engine builds. */
  function fpMath() {
    return [
      Math.acos(0.5), Math.acosh(2), Math.atan(2), Math.atanh(0.5),
      Math.cbrt(2), Math.cos(21), Math.cosh(2), Math.expm1(1),
      Math.log1p(0.5), Math.sinh(2), Math.tan(2), Math.tanh(2)
    ].map(function (v) { return v.toFixed(15); }).join('|');
  }

  /** Screen geometry. */
  function fpScreen() {
    return {
      w: screen.width, h: screen.height,
      cd: screen.colorDepth, pd: screen.pixelDepth,
      dpr: W.devicePixelRatio || 1,
      aw: screen.availWidth, ah: screen.availHeight
    };
  }

  /** Navigator properties. */
  function fpNav() {
    return {
      platform: N.platform,
      hc:       N.hardwareConcurrency || 0,
      mtp:      N.maxTouchPoints || 0,
      dm:       N.deviceMemory || 0,
      lang:     N.language,
      langs:    (N.languages || []).join(','),
      vendor:   N.vendor || '',
      pdf:      !!N.pdfViewerEnabled,
      ce:       !!N.cookieEnabled
    };
  }

  /** Timezone. */
  function fpTZ() {
    try {
      return {
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
        off: new Date().getTimezoneOffset()
      };
    } catch (e) { return { tz: '', off: 0 }; }
  }

  /** Font detection via canvas width measurement. */
  function fpFonts() {
    try {
      var probe = [
        'Arial', 'Arial Black', 'Comic Sans MS', 'Courier New', 'Georgia',
        'Helvetica', 'Impact', 'Lucida Console', 'Palatino Linotype',
        'Tahoma', 'Times New Roman', 'Trebuchet MS', 'Verdana',
        'Menlo', 'Monaco', 'Optima', 'Futura', 'Avenir', 'Didot',
        'American Typewriter', 'Baskerville', 'Copperplate', 'Gill Sans',
        'Roboto', 'Noto Sans', 'Open Sans', 'Lato', 'Montserrat',
        'MS Gothic', 'MS PGothic', 'Segoe UI', 'Candara', 'Constantia'
      ];
      var base = ['monospace', 'sans-serif', 'serif'];
      var c = D.createElement('canvas').getContext('2d');
      if (!c) return '';

      var testStr = 'mmmmmmmmlli10OQ';
      var baseW = {};
      for (var b = 0; b < base.length; b++) {
        c.font = '72px ' + base[b];
        baseW[base[b]] = c.measureText(testStr).width;
      }

      var found = [];
      for (var i = 0; i < probe.length; i++) {
        for (var j = 0; j < base.length; j++) {
          c.font = '72px "' + probe[i] + '",' + base[j];
          if (c.measureText(testStr).width !== baseW[base[j]]) {
            found.push(probe[i]);
            break;
          }
        }
      }
      return found.join(',');
    } catch (e) { return ''; }
  }

  // ==================================================================
  //  MULTI-ANCHOR LOCAL PERSISTENCE
  //  (survives partial storage wipes — any one anchor is enough)
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
    try { W.localStorage.setItem(CFG.storageKey, id); } catch (e) { /* quota / private */ }
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
    } catch (e) { /* ignore */ }
  }

  /** Read from the first anchor that has a value. */
  function readLocal() {
    // Sync sources first (fast)
    var v = getCookie() || getLS();
    if (v) return Promise.resolve(v);
    // Async sources
    return getIDB().then(function (id) {
      if (id) return id;
      return getCacheAPI();
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
  //  IFRAME BRIDGE — Storage Access API (Safari)
  // ==================================================================

  function tryBridge(localId) {
    if (!CFG.serverUrl) return Promise.resolve(null);

    return withTimeout(new Promise(function (resolve) {
      var origin;
      try { origin = new URL(CFG.serverUrl).origin; } catch (_) { resolve(null); return; }

      // Don't bridge if we're already on the identity server's origin
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
          // Bridge is loaded — send our local ID (if any)
          iframe.contentWindow.postMessage({ type: 'ntrx_resolve', id: localId || null }, origin);
        }
        if (e.data.type === 'ntrx_response') {
          cleanup();
          resolve(e.data.id || null);
        }
      }

      W.addEventListener('message', onMsg);

      // Attach iframe to body (must be in DOM for storage access)
      if (D.body) {
        D.body.appendChild(iframe);
      } else {
        D.addEventListener('DOMContentLoaded', function () { D.body.appendChild(iframe); });
      }
    }), 3500);
  }

  // ==================================================================
  //  SERVER RESOLUTION
  // ==================================================================

  function resolveServer(fingerprints, localId) {
    if (!CFG.serverUrl) return Promise.resolve(null);

    var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctrl) ctrl.abort(); }, CFG.timeout);

    return fetch(CFG.serverUrl + CFG.resolvePath, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        core:    fingerprints.core,
        device:  fingerprints.device,
        full:    fingerprints.full,
        signals: fingerprints.signals,
        localId: localId || null,
        site:    W.location.hostname,
        ts:      Date.now()
      }),
      signal: ctrl ? ctrl.signal : undefined
    }).then(function (r) {
      clearTimeout(timer);
      return r.ok ? r.json().then(function (d) { return d.id || null; }) : null;
    }).catch(function () {
      clearTimeout(timer);
      return null;
    });
  }

  // ==================================================================
  //  ORCHESTRATOR
  // ==================================================================

  function main() {
    // Collect audio fingerprint (async) then continue
    fpAudio().then(function (audioHash) {

      // Gather all synchronous signals
      var canvas  = fpCanvas();
      var webgl   = fpWebGL();
      var scr     = fpScreen();
      var nav     = fpNav();
      var tz      = fpTZ();
      var fonts   = fpFonts();
      var math    = fpMath();

      var signals = {
        canvas: canvas, webgl: webgl, screen: scr,
        nav: nav, tz: tz, fonts: fonts, math: math, audio: audioHash
      };

      // Tiered hash computation
      var coreStr = stableJSON({
        canvas:  canvas,
        wglR:    webgl ? webgl.renderer : '',
        wglV:    webgl ? webgl.vendor : '',
        wglRH:   webgl ? webgl.renderHash : 0,
        audio:   audioHash
      });

      var deviceStr = stableJSON({
        platform: nav.platform,
        hc:  nav.hc,
        mtp: nav.mtp,
        dm:  nav.dm,
        sw:  scr.w,
        sh:  scr.h,
        cd:  scr.cd,
        dpr: scr.dpr,
        tz:  tz.tz,
        math: math
      });

      var fullStr = stableJSON(signals);

      // Compute hashes + read local stores in parallel
      Promise.all([
        sha256(coreStr),
        sha256(deviceStr),
        sha256(fullStr),
        readLocal()
      ]).then(function (r) {
        var coreHash   = r[0];
        var deviceHash = r[1];
        var fullHash   = r[2];
        var localId    = r[3];

        var fp = {
          core:    coreHash,
          device:  deviceHash,
          full:    fullHash,
          signals: {
            webglRenderer: webgl ? webgl.renderer : '',
            webglVendor:   webgl ? webgl.vendor : '',
            platform: nav.platform,
            hc:  nav.hc,
            mtp: nav.mtp,
            dm:  nav.dm,
            sw:  scr.w,
            sh:  scr.h,
            cd:  scr.cd,
            dpr: scr.dpr,
            tz:  tz.tz,
            math: math,
            langCount: (nav.langs || '').split(',').length
          }
        };

        // --- Resolution cascade ---

        // 1. Server resolution (primary — handles cross-site via fingerprint graph)
        resolveServer(fp, localId).then(function (serverId) {
          if (serverId) {
            writeLocal(serverId);
            emit(serverId);
            return;
          }

          // 2. Existing local ID is usable if server was unreachable
          if (localId && localId.indexOf(CFG.prefix) === 0) {
            writeLocal(localId); // re-persist across all anchors
            emit(localId);
            return;
          }

          // 3. Iframe bridge (Storage Access API — Safari)
          tryBridge(localId).then(function (bridgeId) {
            if (bridgeId && bridgeId.indexOf(CFG.prefix) === 0) {
              writeLocal(bridgeId);
              emit(bridgeId);
              return;
            }

            // 4. Client-side fallback — deterministic from fingerprint
            var fallback = CFG.prefix + coreHash.slice(0, 8) + '-' +
              deviceHash.slice(0, 4) + '-' + fullHash.slice(0, 4) + '-' +
              coreHash.slice(8, 12) + '-' + fullHash.slice(4, 16);
            writeLocal(fallback);
            emit(fallback);
          });
        });
      });
    });
  }

  /** Final output. */
  function emit(id) {
    // Console output (required by spec)
    console.log('ID: ' + id);

    // Expose programmatically
    W.__ntrx_id = id;

    // Dispatch event for downstream integrations
    try {
      W.dispatchEvent(new CustomEvent('ntrx:identified', { detail: { id: id } }));
    } catch (e) { /* old IE */ }
  }

  // ==================================================================
  //  BOOTSTRAP — wait for DOM if needed, then run
  // ==================================================================
  if (D.readyState === 'loading') {
    D.addEventListener('DOMContentLoaded', main);
  } else {
    // Tiny defer so we don't block page paint
    setTimeout(main, 0);
  }

})(window, document, navigator);
