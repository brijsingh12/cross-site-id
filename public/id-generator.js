/**
 * Cross-Site Identity Generator v4.0 — Full Intelligence Stack
 * ==============================================================
 * Safari-first | Zero collisions | ML-based identity recovery
 *
 * 7 Signal Categories:
 *   1. Browser Fingerprint  — canvas, WebGL, audio, math, fonts
 *   2. IP Intelligence      — collected server-side (subnet, ASN)
 *   3. Device Intelligence  — GPU, screen, hardware, OS, browser
 *   4. Behavioral Signals   — mouse velocity, scroll, interaction timing
 *   5. Header Fingerprint   — server-side (Accept, Accept-Language order)
 *   6. Timezone / Locale    — tz, date/number formatting, languages
 *   7. Historical Matching  — time-of-day, visit patterns (server-side)
 *
 * Resolution cascade:
 *   1. Bounce token in URL (returning from Safari redirect)
 *   2. Local anchors (Cookie + localStorage + IndexedDB + CacheAPI)
 *   3. Iframe bridge (Chrome/Firefox — skipped on WebKit)
 *   4. Auto bounce redirect (Safari/WebKit/Instagram)
 *   5. Server ML recovery (all signals → weighted similarity matching)
 *   6. Generate new UUID
 */
(function (W, D, N) {
  'use strict';

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
    recoverPath:  '/api/recover',
    bouncePath:   '/bounce',
    bounceSetPath:'/bounce-set',
    cookieDays:   400,
    timeout:      5000,
    serverUrl:    ''
  };

  // ── Auto-detect server ──
  (function () {
    var scripts = D.getElementsByTagName('script');
    for (var i = scripts.length - 1; i >= 0; i--) {
      var s = scripts[i].src || '';
      if (s.indexOf('id-generator') !== -1) {
        try { CFG.serverUrl = new URL(s).origin; }
        catch (_) { var a = D.createElement('a'); a.href = s; CFG.serverUrl = a.protocol + '//' + a.host; }
        break;
      }
    }
  })();

  // ── Browser detection ──
  var isWebKit = /AppleWebKit/.test(N.userAgent) && !/Chrome\//.test(N.userAgent) && !/Chromium\//.test(N.userAgent);

  // ==================================================================
  //  UTILITIES
  // ==================================================================

  function generateUUID() {
    if (W.crypto && W.crypto.randomUUID) return CFG.prefix + W.crypto.randomUUID();
    if (W.crypto && W.crypto.getRandomValues) {
      var b = new Uint8Array(16); W.crypto.getRandomValues(b);
      b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
      var h = '';
      for (var i = 0; i < 16; i++) { h += b[i].toString(16).padStart(2, '0'); if (i===3||i===5||i===7||i===9) h += '-'; }
      return CFG.prefix + h;
    }
    return CFG.prefix + 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      var r = Math.random()*16|0; return (c==='x'?r:(r&0x3|0x8)).toString(16);
    });
  }

  function valid(id) { return id && typeof id === 'string' && id.indexOf(CFG.prefix) === 0 && id.length > 10; }

  function hex(buf) {
    for (var h='', v=new Uint8Array(buf), i=0; i<v.length; i++) h += v[i].toString(16).padStart(2,'0');
    return h;
  }

  function sha256(str) {
    if (W.crypto && W.crypto.subtle) return W.crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)).then(hex);
    var a=5381, b=52711;
    for (var i=0; i<str.length; i++) { var c=str.charCodeAt(i); a=((a<<5)+a+c)>>>0; b=((b<<5)+b+c)>>>0; }
    var s = a.toString(16)+b.toString(16);
    while (s.length<64) s += ((a*b+s.length)>>>0).toString(16);
    return Promise.resolve(s.slice(0,64));
  }

  function withTimeout(promise, ms) {
    return new Promise(function(resolve) {
      var done=false;
      var t=setTimeout(function(){if(!done){done=true;resolve(null);}},ms);
      promise.then(function(v){if(!done){done=true;clearTimeout(t);resolve(v);}})
             .catch(function(){if(!done){done=true;clearTimeout(t);resolve(null);}});
    });
  }

  // ==================================================================
  //  SIGNAL COLLECTORS
  // ==================================================================

  // ── 1. Browser Fingerprint ──

  function fpCanvas() {
    try {
      var c=D.createElement('canvas'); c.width=300; c.height=80;
      var x=c.getContext('2d'); if(!x)return '';
      var lg=x.createLinearGradient(0,0,300,0);
      lg.addColorStop(0,'#ff6b6b'); lg.addColorStop(0.5,'#4ecdc4'); lg.addColorStop(1,'#45b7d1');
      x.fillStyle=lg; x.fillRect(0,0,300,80);
      x.globalAlpha=0.7; x.fillStyle='#e74c3c';
      x.beginPath(); x.arc(55,35,28,0,Math.PI*2); x.fill();
      x.fillStyle='#3498db'; x.beginPath(); x.arc(95,35,28,0,Math.PI*2); x.fill();
      x.globalAlpha=1;
      x.strokeStyle='#6c5ce7'; x.lineWidth=2.5; x.beginPath();
      x.moveTo(0,60); x.bezierCurveTo(75,10,225,70,300,20); x.stroke();
      x.fillStyle='#2d3436'; x.font='bold 17px Arial,sans-serif';
      x.fillText('Cwm fjord veg balks nth pyx quiz',6,28);
      x.fillStyle='#636e72'; x.font='italic 13px Georgia,serif';
      x.fillText('\u00c0\u00e7\u00fc\u00f1 0123456789',6,72);
      return c.toDataURL();
    } catch(e){return '';}
  }

  function fpWebGL() {
    try {
      var c=D.createElement('canvas');
      var gl=c.getContext('webgl')||c.getContext('experimental-webgl'); if(!gl)return null;
      var dbg=gl.getExtension('WEBGL_debug_renderer_info');
      return {
        vendor: dbg?gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL):gl.getParameter(gl.VENDOR),
        renderer: dbg?gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL):gl.getParameter(gl.RENDERER),
        version: gl.getParameter(gl.VERSION),
        maxTex: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        maxVP: Array.from(gl.getParameter(gl.MAX_VIEWPORT_DIMS)||[]),
        exts: (gl.getSupportedExtensions()||[]).sort().join(',')
      };
    } catch(e){return null;}
  }

  function fpAudio() {
    return new Promise(function(resolve) {
      try {
        var AC=W.OfflineAudioContext||W.webkitOfflineAudioContext; if(!AC){resolve('');return;}
        var ctx=new AC(1,5000,44100);
        var osc=ctx.createOscillator(); osc.type='triangle'; osc.frequency.setValueAtTime(10000,ctx.currentTime);
        var comp=ctx.createDynamicsCompressor();
        comp.threshold.setValueAtTime(-50,ctx.currentTime); comp.knee.setValueAtTime(40,ctx.currentTime);
        comp.ratio.setValueAtTime(12,ctx.currentTime); comp.attack.setValueAtTime(0,ctx.currentTime);
        comp.release.setValueAtTime(0.25,ctx.currentTime);
        osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
        var settled=false;
        ctx.startRendering().then(function(buf) {
          if(settled)return; settled=true;
          var d=buf.getChannelData(0), sum=0;
          for(var i=4500;i<5000;i++) sum+=Math.abs(d[i]);
          resolve(sum.toFixed(8));
        }).catch(function(){if(!settled){settled=true;resolve('');}});
        setTimeout(function(){if(!settled){settled=true;resolve('');}},2000);
      } catch(e){resolve('');}
    });
  }

  function fpMath() {
    return [Math.acos(0.5),Math.acosh(2),Math.atan(2),Math.atanh(0.5),
            Math.cbrt(2),Math.cos(21),Math.cosh(2),Math.expm1(1),
            Math.log1p(0.5),Math.sinh(2),Math.tan(2),Math.tanh(2)]
      .map(function(v){return v.toFixed(15);}).join('|');
  }

  function fpFonts() {
    try {
      var probe=['Arial','Arial Black','Comic Sans MS','Courier New','Georgia','Helvetica',
        'Impact','Lucida Console','Palatino Linotype','Tahoma','Times New Roman','Trebuchet MS',
        'Verdana','Menlo','Monaco','Optima','Futura','Avenir','Avenir Next','Didot',
        'American Typewriter','Baskerville','Copperplate','Gill Sans','Marker Felt','Zapfino',
        'Roboto','Noto Sans','Open Sans','Lato','Montserrat','Source Sans Pro','Inter',
        'Fira Code','JetBrains Mono','Cascadia Code','Segoe UI','Calibri','Cambria',
        'Helvetica Neue','SF Pro','SF Mono','DIN Alternate','Proxima Nova'];
      var base=['monospace','sans-serif','serif'];
      var c=D.createElement('canvas').getContext('2d'); if(!c)return '';
      var ts='mmmmmmmmlli10OQ@#', bw={};
      for(var b=0;b<base.length;b++){c.font='72px '+base[b]; bw[base[b]]=c.measureText(ts).width;}
      var found=[];
      for(var i=0;i<probe.length;i++) for(var j=0;j<base.length;j++){
        c.font='72px "'+probe[i]+'",'+base[j];
        if(c.measureText(ts).width!==bw[base[j]]){found.push(probe[i]);break;}
      }
      return found.join(',');
    } catch(e){return '';}
  }

  // ── 3. Device Intelligence ──

  function collectDevice(webgl) {
    return {
      gpu: webgl ? webgl.renderer : '',
      gpuVendor: webgl ? webgl.vendor : '',
      screenW: screen.width,
      screenH: screen.height,
      availW: screen.availWidth,
      availH: screen.availHeight,
      dpr: W.devicePixelRatio || 1,
      colorDepth: screen.colorDepth,
      hardwareConcurrency: N.hardwareConcurrency || 0,
      maxTouchPoints: N.maxTouchPoints || 0,
      deviceMemory: N.deviceMemory || 0,
      platform: N.platform
    };
  }

  // ── 4. Behavioral Signals ──

  var behaviorData = { mousePositions: [], scrollPositions: [], firstInteraction: null };

  function startBehaviorCollection() {
    function onMouse(e) {
      if (!behaviorData.firstInteraction) behaviorData.firstInteraction = Date.now();
      behaviorData.mousePositions.push({ x: e.clientX, y: e.clientY, t: Date.now() });
      if (behaviorData.mousePositions.length > 50) {
        D.removeEventListener('mousemove', onMouse);
      }
    }
    function onScroll() {
      if (!behaviorData.firstInteraction) behaviorData.firstInteraction = Date.now();
      behaviorData.scrollPositions.push({ y: W.scrollY, t: Date.now() });
      if (behaviorData.scrollPositions.length > 30) {
        W.removeEventListener('scroll', onScroll);
      }
    }
    function onTouch() {
      if (!behaviorData.firstInteraction) behaviorData.firstInteraction = Date.now();
    }
    D.addEventListener('mousemove', onMouse, { passive: true });
    W.addEventListener('scroll', onScroll, { passive: true });
    D.addEventListener('touchstart', onTouch, { passive: true });
  }

  function computeBehavior() {
    var result = { mouseSpeed: 0, scrollSpeed: 0, interactionBucket: 'none' };
    var mp = behaviorData.mousePositions;

    // Mouse velocity (pixels per second)
    if (mp.length >= 5) {
      var totalDist = 0, totalTime = 0;
      for (var i = 1; i < mp.length; i++) {
        var dx = mp[i].x - mp[i-1].x, dy = mp[i].y - mp[i-1].y;
        totalDist += Math.sqrt(dx*dx + dy*dy);
        totalTime += mp[i].t - mp[i-1].t;
      }
      result.mouseSpeed = totalTime > 0 ? Math.round(totalDist / totalTime * 1000) : 0;
    }

    // Scroll velocity
    var sp = behaviorData.scrollPositions;
    if (sp.length >= 3) {
      var sDist = 0, sTime = 0;
      for (var j = 1; j < sp.length; j++) {
        sDist += Math.abs(sp[j].y - sp[j-1].y);
        sTime += sp[j].t - sp[j-1].t;
      }
      result.scrollSpeed = sTime > 0 ? Math.round(sDist / sTime * 1000) : 0;
    }

    // Interaction timing bucket
    if (behaviorData.firstInteraction) {
      var delay = behaviorData.firstInteraction - W.__ntrx_loadTime;
      result.interactionBucket = delay < 2000 ? 'fast' : delay < 8000 ? 'medium' : 'slow';
    }

    return result;
  }

  // ── 6. Timezone / Locale ──

  function collectLocale() {
    var d = new Date(2024, 0, 15, 13, 45, 30);
    return {
      timezone: (function(){try{return Intl.DateTimeFormat().resolvedOptions().timeZone;}catch(e){return '';}})(),
      offset: new Date().getTimezoneOffset(),
      languages: (N.languages || []).join(','),
      dateFormat: (function(){try{return d.toLocaleDateString();}catch(e){return '';}})(),
      numberFormat: (function(){try{return (1234567.89).toLocaleString();}catch(e){return '';}})()
    };
  }

  // ==================================================================
  //  LOCAL PERSISTENCE (4 anchors)
  // ==================================================================

  function getCookie(){var re=new RegExp('(?:^|;\\s*)'+CFG.cookieName.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'=([^;]+)');var m=D.cookie.match(re);return m?decodeURIComponent(m[1]):null;}
  function setCookie(id){var exp=new Date(Date.now()+CFG.cookieDays*864e5).toUTCString();D.cookie=CFG.cookieName+'='+encodeURIComponent(id)+';expires='+exp+';path=/;SameSite=Lax;Secure';}
  function getLS(){try{return W.localStorage.getItem(CFG.storageKey);}catch(e){return null;}}
  function setLS(id){try{W.localStorage.setItem(CFG.storageKey,id);}catch(e){}}
  function idbOpen(){return new Promise(function(ok,fail){try{var r=W.indexedDB.open(CFG.idbName,1);r.onupgradeneeded=function(){r.result.createObjectStore(CFG.idbStore);};r.onsuccess=function(){ok(r.result);};r.onerror=function(){fail(r.error);};}catch(e){fail(e);}});}
  function getIDB(){return idbOpen().then(function(db){return new Promise(function(ok){var tx=db.transaction(CFG.idbStore,'readonly');var r=tx.objectStore(CFG.idbStore).get('uid');r.onsuccess=function(){ok(r.result||null);};r.onerror=function(){ok(null);};});}).catch(function(){return null;});}
  function setIDB(id){return idbOpen().then(function(db){var tx=db.transaction(CFG.idbStore,'readwrite');tx.objectStore(CFG.idbStore).put(id,'uid');}).catch(function(){});}
  function getCacheAPI(){if(!W.caches)return Promise.resolve(null);return W.caches.open(CFG.cacheName).then(function(c){return c.match(new Request(CFG.cacheKey)).then(function(r){return r?r.text():null;});}).catch(function(){return null;});}
  function setCacheAPI(id){if(!W.caches)return;try{W.caches.open(CFG.cacheName).then(function(c){c.put(new Request(CFG.cacheKey),new Response(id,{headers:{'Content-Type':'text/plain'}}));}).catch(function(){});}catch(e){}}

  function readLocal(){var v=getCookie()||getLS();if(valid(v))return Promise.resolve(v);return getIDB().then(function(id){if(valid(id))return id;return getCacheAPI().then(function(cid){return valid(cid)?cid:null;});});}
  function writeLocal(id){setCookie(id);setLS(id);setIDB(id);setCacheAPI(id);}

  // ==================================================================
  //  BOUNCE REDIRECT (Safari cross-site mechanism)
  // ==================================================================

  function extractBounceToken() {
    try {
      var params = new URLSearchParams(W.location.search);
      var tok = params.get('_ntrx_tok');
      if (valid(tok)) {
        params.delete('_ntrx_tok');
        var clean = W.location.pathname + (params.toString() ? '?' + params.toString() : '') + W.location.hash;
        try { W.history.replaceState(null, '', clean); } catch(e) {}
        try { W.sessionStorage.setItem(CFG.bounceFlag, '1'); } catch(e) {}
        return tok;
      }
    } catch(e) {}
    return null;
  }

  function doBounce() {
    if (!CFG.serverUrl) return false;
    try { if (W.sessionStorage.getItem(CFG.bounceFlag)) return false; W.sessionStorage.setItem(CFG.bounceFlag, '1'); } catch(e) {}
    var returnUrl = W.location.href;
    try { var u = new URL(returnUrl); u.searchParams.delete('_ntrx_tok'); returnUrl = u.toString(); } catch(e) {}
    W.location.replace(CFG.serverUrl + CFG.bouncePath + '?r=' + encodeURIComponent(returnUrl));
    return true;
  }

  function silentBounceSet(id) {
    if (!CFG.serverUrl) return;
    var img = new Image();
    img.src = CFG.serverUrl + CFG.bounceSetPath + '?t=' + encodeURIComponent(id) + '&_=' + Date.now();
  }

  // ==================================================================
  //  IFRAME BRIDGE (Chrome/Firefox only)
  // ==================================================================

  function tryBridge(localId) {
    if (isWebKit || !CFG.serverUrl) return Promise.resolve(null);
    return withTimeout(new Promise(function(resolve) {
      var origin; try{origin=new URL(CFG.serverUrl).origin;}catch(_){resolve(null);return;}
      if(W.location.origin===origin){resolve(null);return;}
      var iframe=D.createElement('iframe');
      iframe.style.cssText='position:fixed;width:0;height:0;border:0;opacity:0;pointer-events:none';
      iframe.src=CFG.serverUrl+CFG.bridgePath;
      function cleanup(){W.removeEventListener('message',onMsg);try{if(iframe.parentNode)iframe.parentNode.removeChild(iframe);}catch(e){}}
      function onMsg(e){if(e.origin!==origin||!e.data)return;if(e.data.type==='ntrx_bridge_ready'){iframe.contentWindow.postMessage({type:'ntrx_resolve',id:localId||null},origin);}if(e.data.type==='ntrx_response'){cleanup();resolve(e.data.id||null);}}
      W.addEventListener('message',onMsg);
      if(D.body)D.body.appendChild(iframe);else D.addEventListener('DOMContentLoaded',function(){D.body.appendChild(iframe);});
    }), 3500);
  }

  function pushToBridge(id) {
    if (isWebKit || !CFG.serverUrl) return;
    var origin;try{origin=new URL(CFG.serverUrl).origin;}catch(_){return;}
    if(W.location.origin===origin)return;
    var iframe=D.createElement('iframe');
    iframe.style.cssText='position:fixed;width:0;height:0;border:0;opacity:0;pointer-events:none';
    iframe.src=CFG.serverUrl+CFG.bridgePath;
    function cleanup(){W.removeEventListener('message',h);try{if(iframe.parentNode)iframe.parentNode.removeChild(iframe);}catch(e){}}
    var tm=setTimeout(cleanup,4000);
    function h(e){if(e.origin!==origin||!e.data)return;if(e.data.type==='ntrx_bridge_ready'){iframe.contentWindow.postMessage({type:'ntrx_store',id:id},origin);}if(e.data.type==='ntrx_stored'){clearTimeout(tm);cleanup();}}
    W.addEventListener('message',h);
    if(D.body)D.body.appendChild(iframe);else D.addEventListener('DOMContentLoaded',function(){D.body.appendChild(iframe);});
  }

  // ==================================================================
  //  SERVER COMMUNICATION
  // ==================================================================

  /** Register token + send all collected signals to build the profile. */
  function registerWithServer(id, signals) {
    if (!CFG.serverUrl) return;
    var body = JSON.stringify({
      id: id,
      site: W.location.hostname,
      fingerprint: signals.fingerprint || {},
      device: signals.device || {},
      locale: signals.locale || {},
      behavior: signals.behavior || {},
      ts: Date.now()
    });
    try {
      if (N.sendBeacon) N.sendBeacon(CFG.serverUrl + CFG.registerPath, new Blob([body], {type:'application/json'}));
      else fetch(CFG.serverUrl + CFG.registerPath, {method:'POST',headers:{'Content-Type':'application/json'},body:body,keepalive:true}).catch(function(){});
    } catch(e){}
  }

  /** Try to recover a lost identity via ML matching on the server. */
  function tryServerRecovery(signals) {
    if (!CFG.serverUrl) return Promise.resolve(null);
    return withTimeout(
      fetch(CFG.serverUrl + CFG.recoverPath, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          site: W.location.hostname,
          fingerprint: signals.fingerprint || {},
          device: signals.device || {},
          locale: signals.locale || {},
          behavior: signals.behavior || {}
        })
      }).then(function(r) { return r.ok ? r.json() : null; })
        .then(function(d) { return d && d.recovered && valid(d.id) ? d.id : null; }),
      CFG.timeout
    );
  }

  // ==================================================================
  //  DEFERRED BEHAVIOR UPDATE
  //  Sends behavioral signals after user has interacted for 5 seconds.
  // ==================================================================

  function scheduleBehaviorUpdate(id) {
    setTimeout(function () {
      var beh = computeBehavior();
      if (beh.mouseSpeed > 0 || beh.scrollSpeed > 0) {
        registerWithServer(id, { behavior: beh });
      }
    }, 5000);
  }

  // ==================================================================
  //  ORCHESTRATOR
  // ==================================================================

  function main() {
    W.__ntrx_loadTime = Date.now();
    startBehaviorCollection();

    // ── Step 1: bounce token in URL ──
    var bounceId = extractBounceToken();
    if (bounceId) {
      writeLocal(bounceId);
      collectAndRegister(bounceId);
      pushToBridge(bounceId);
      emit(bounceId);
      return;
    }

    // ── Step 2: local anchors ──
    readLocal().then(function(localId) {
      if (localId) {
        writeLocal(localId);
        collectAndRegister(localId);
        emit(localId);
        return;
      }

      // ── Step 3: iframe bridge (Chrome/Firefox) ──
      tryBridge(null).then(function(bridgeId) {
        if (valid(bridgeId)) {
          writeLocal(bridgeId);
          collectAndRegister(bridgeId);
          emit(bridgeId);
          return;
        }

        // ── Step 4: auto bounce (Safari/WebKit/Instagram) ──
        if (isWebKit) {
          if (doBounce()) return; // page navigating away
        }

        // ── Step 5: ML-based identity recovery on server ──
        collectSignals().then(function(signals) {
          tryServerRecovery(signals).then(function(recoveredId) {
            if (recoveredId) {
              writeLocal(recoveredId);
              registerWithServer(recoveredId, signals);
              pushToBridge(recoveredId);
              silentBounceSet(recoveredId);
              scheduleBehaviorUpdate(recoveredId);
              emit(recoveredId);
              return;
            }

            // ── Step 6: truly new device — generate UUID ──
            var newId = generateUUID();
            writeLocal(newId);
            registerWithServer(newId, signals);
            pushToBridge(newId);
            silentBounceSet(newId);
            scheduleBehaviorUpdate(newId);
            emit(newId);
          });
        });
      });
    });
  }

  /** Collect all synchronous + async signals, return as promise. */
  function collectSignals() {
    var webgl = fpWebGL();
    var canvas = fpCanvas();
    var math = fpMath();
    var fonts = fpFonts();
    var device = collectDevice(webgl);
    var locale = collectLocale();

    return fpAudio().then(function(audioHash) {
      return Promise.all([
        sha256(canvas || ''),
        sha256(math),
        sha256(fonts || '')
      ]).then(function(hashes) {
        return {
          fingerprint: {
            canvasHash: hashes[0],
            webglRenderer: webgl ? webgl.renderer : '',
            webglVendor: webgl ? webgl.vendor : '',
            audioHash: audioHash,
            mathHash: hashes[1],
            fontsHash: hashes[2]
          },
          device: device,
          locale: locale
        };
      });
    });
  }

  /** Collect signals and register with server. */
  function collectAndRegister(id) {
    collectSignals().then(function(signals) {
      registerWithServer(id, signals);
      scheduleBehaviorUpdate(id);
    });
  }

  function emit(id) {
    console.log('ID: ' + id);
    W.__ntrx_id = id;
    try { W.dispatchEvent(new CustomEvent('ntrx:identified', { detail: { id: id } })); } catch(e){}
  }

  // ── Bootstrap ──
  if (D.readyState === 'loading') D.addEventListener('DOMContentLoaded', main);
  else setTimeout(main, 0);

})(window, document, navigator);
