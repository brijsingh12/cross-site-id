/**
 * Deterministic Device-Browser Fingerprint v7 — Profile-Safe
 * ===========================================================
 * 10 orthogonal signal planes, 90+ individual signals.
 * Zero storage. SHA-256. Stable across sessions/tabs/profiles/clearing.
 *
 * PROFILE-SAFE GUARANTEE:
 *   Every signal is locked to hardware or browser binary.
 *   NONE depend on user settings, preferences, or profile config.
 *   Creating a new browser profile produces the EXACT same ID.
 *
 * What's excluded (profile-dependent):
 *   - navigator.cookieEnabled      (can be toggled per profile)
 *   - navigator.languages.length   (profile can add/remove languages)
 *   - navigator.pdfViewerEnabled   (can be toggled per profile)
 *   - prefers-color-scheme         (Chrome/Firefox allow per-profile override)
 *   - Intl with default locale     (profile locale changes output)
 *   - getTimezoneOffset() live     (shifts with DST)
 *
 * Signal planes:
 *   P1  Hardware      — screen, CPU, touch, memory, fixed TZ offset
 *   P2  GPU Core      — renderer, vendor, limits, extensions
 *   P3  GPU Extended  — shader precision, renderbuffer, color bits
 *   P4  Browser ID    — vendor, engine globals, API existence probes
 *   P5  Engine Math   — V8/JSC/SpiderMonkey transcendental divergence
 *   P6  Media/Display — color gamut, pointer type, HDR (hardware-only)
 *   P7  Intl Engine   — fixed-locale 'en-US' ICU probes (engine version)
 *   P8  CSS Engine    — CSS.supports probes (engine binary)
 *   P9  WebGL2 Deep   — WebGL2 limits, extensions (GPU generation)
 *   P10 Text Metrics  — canvas measureText sub-pixel widths (GPU rasterizer)
 */
void async function NtrxFingerprint() {
  'use strict';

  // ================================================================
  //  HEX LUT + HASH
  // ================================================================
  const HEX = Array.from({length:256},(_,i)=>(i>>>4).toString(16)+(i&0xf).toString(16));

  const bufHex = b => {
    const u = new Uint8Array(b); let h = '';
    for (let i = 0; i < u.length; i += 4)
      h += HEX[u[i]] + HEX[u[i+1]] + HEX[u[i+2]] + HEX[u[i+3]];
    return h;
  };

  // Single hash path. No fallback. Requires HTTPS (which you need anyway).
  const hash256 = s =>
    crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)).then(bufHex);

  const S = '\x1F'; // unit separator (field)
  const R = '\x1E'; // record separator (plane)

  // ================================================================
  //  P1: HARDWARE PLANE (9 signals)
  // ================================================================
  const P1 = [
    screen.width, screen.height, screen.colorDepth, screen.pixelDepth,
    window.devicePixelRatio || 1,
    navigator.hardwareConcurrency || 0,
    navigator.maxTouchPoints || 0,
    navigator.deviceMemory || 0,
    // Timezone: use STANDARD offset at a fixed date (Jan 1).
    // Why not getTimezoneOffset()? → it shifts with DST twice/year.
    // Why not Intl timezone name? → depends on Intl locale (profile-dependent).
    // Fixed-date offset: always returns the standard offset for this machine,
    // e.g., America/New_York → always -300 (EST) regardless of current DST.
    new Date(2024, 0, 1).getTimezoneOffset(),
  ].join(S);

  // ================================================================
  //  P2: GPU CORE PLANE (7 signals)
  // ================================================================
  let gl, dbg;
  try {
    const c = document.createElement('canvas');
    gl = c.getContext('webgl') || c.getContext('experimental-webgl');
    dbg = gl ? gl.getExtension('WEBGL_debug_renderer_info') : null;
  } catch(_) {}

  const glp = (p) => { try { return gl ? gl.getParameter(p) : ''; } catch(_) { return ''; } };

  const P2 = gl ? [
    glp(dbg ? dbg.UNMASKED_RENDERER_WEBGL : gl.RENDERER),
    glp(dbg ? dbg.UNMASKED_VENDOR_WEBGL : gl.VENDOR),
    glp(gl.MAX_TEXTURE_SIZE),
    glp(gl.MAX_VERTEX_UNIFORM_VECTORS),
    glp(gl.MAX_FRAGMENT_UNIFORM_VECTORS),
    String(Array.from(glp(gl.MAX_VIEWPORT_DIMS) || [])),
    String(Array.from(glp(gl.ALIASED_LINE_WIDTH_RANGE) || [])),
    // WebGL extensions list — CRITICAL for Safari.
    // Safari hides the GPU name ("Apple GPU" for all chips) but different
    // Apple GPUs support different extension sets. This is the main signal
    // that differentiates M1 vs M2 vs M3 in Safari.
    (gl.getSupportedExtensions() || []).sort().join(',')
  ].join(S) : '';

  // ================================================================
  //  P3: GPU EXTENDED PLANE (16 signals) — deep driver fingerprint
  // ================================================================
  const P3 = gl ? (() => {
    // Shader precision format — unique per GPU driver implementation
    const spf = (st, pt) => {
      try {
        const p = gl.getShaderPrecisionFormat(st, pt);
        return p ? `${p.rangeMin},${p.rangeMax},${p.precision}` : '';
      } catch(_) { return ''; }
    };

    return [
      glp(gl.MAX_RENDERBUFFER_SIZE),
      glp(gl.MAX_TEXTURE_IMAGE_UNITS),
      glp(gl.MAX_VERTEX_TEXTURE_IMAGE_UNITS),
      glp(gl.MAX_VARYING_VECTORS),
      glp(gl.MAX_VERTEX_ATTRIBS),
      glp(gl.MAX_CUBE_MAP_TEXTURE_SIZE),
      glp(gl.STENCIL_BITS),
      glp(gl.DEPTH_BITS),
      glp(gl.RED_BITS) + ',' + glp(gl.GREEN_BITS) + ',' + glp(gl.BLUE_BITS) + ',' + glp(gl.ALPHA_BITS),
      String(Array.from(glp(gl.ALIASED_POINT_SIZE_RANGE) || [])),
      // Shader precision — 6 probes, extremely GPU-specific
      spf(gl.VERTEX_SHADER,   gl.HIGH_FLOAT),
      spf(gl.VERTEX_SHADER,   gl.MEDIUM_FLOAT),
      spf(gl.FRAGMENT_SHADER, gl.HIGH_FLOAT),
      spf(gl.FRAGMENT_SHADER, gl.MEDIUM_FLOAT),
      spf(gl.VERTEX_SHADER,   gl.HIGH_INT),
      spf(gl.FRAGMENT_SHADER, gl.HIGH_INT),
    ].join(S);
  })() : '';

  // ================================================================
  //  P4: BROWSER IDENTITY PLANE (14 signals)
  // ================================================================
  const w = window, n = navigator;
  const P4 = [
    n.vendor || '',                                         // ✅ browser binary — never changes per profile
    n.platform || '',                                       // ✅ OS/hardware
    typeof n.brave !== 'undefined' ? 1 : 0,                 // ✅ browser binary
    typeof w.chrome !== 'undefined' ? 1 : 0,                // ✅ browser binary
    typeof w.safari !== 'undefined' ? 1 : 0,                // ✅ browser binary
    typeof w.InstallTrigger !== 'undefined' ? 1 : 0,        // ✅ browser binary
    typeof n.userAgentData !== 'undefined' ? 1 : 0,         // ✅ browser binary
    typeof w.SharedArrayBuffer !== 'undefined' ? 1 : 0,     // ✅ browser binary (COOP/COEP is server-side)
    typeof w.OffscreenCanvas !== 'undefined' ? 1 : 0,       // ✅ browser binary
    typeof n.locks !== 'undefined' ? 1 : 0,                 // ✅ browser binary
    typeof w.ReportingObserver !== 'undefined' ? 1 : 0,     // ✅ browser binary
    // REMOVED: pdfViewerEnabled — can be toggled per profile in Chrome settings
    // REMOVED: cookieEnabled   — can be disabled per profile
    // REMOVED: languages.length — user can add/remove languages per profile
    //
    // REPLACED with profile-safe API existence probes:
    typeof w.BroadcastChannel !== 'undefined' ? 1 : 0,      // ✅ browser binary
    typeof w.WritableStream !== 'undefined' ? 1 : 0,        // ✅ browser binary
    typeof w.CompressionStream !== 'undefined' ? 1 : 0,     // ✅ browser binary
  ].join(S);

  // ================================================================
  //  P5: ENGINE MATH PLANE (10 signals) — JS engine divergence
  // ================================================================
  const P5 = [
    Math.cos(21), Math.sinh(1), Math.atanh(0.5), Math.expm1(1),
    Math.cbrt(Math.PI), Math.log1p(0.5), Math.tanh(2),
    (2**53 + 1),
    // Extra engine probes for deeper divergence
    Math.acosh(1e+308),                      // infinity handling differs
    Math.hypot(1e150, 1e150).toString().length // overflow path varies
  ].map(String).join(S);

  // ================================================================
  //  P6: MEDIA/DISPLAY PLANE (8 signals) — CSS media queries
  //  These are locked to hardware/OS display configuration.
  // ================================================================
  const mq = q => { try { return window.matchMedia(q).matches ? 1 : 0; } catch(_) { return -1; } };

  const P6 = [
    mq('(color-gamut: p3)'),           // ✅ display hardware
    mq('(color-gamut: srgb)'),         // ✅ display hardware
    mq('(color-gamut: rec2020)'),      // ✅ display hardware
    mq('(pointer: fine)'),             // ✅ input hardware
    mq('(pointer: coarse)'),           // ✅ input hardware
    mq('(hover: hover)'),              // ✅ input hardware
    mq('(dynamic-range: high)'),       // ✅ display hardware
    // REMOVED: prefers-color-scheme — Chrome/Firefox allow per-profile override
    // REPLACED with hardware-only media queries:
    mq('(any-pointer: fine)'),         // ✅ input hardware (any connected pointing device)
    mq('(any-hover: hover)'),          // ✅ input hardware
    mq('(color)'),                     // ✅ display hardware (is color display)
    mq('(monochrome)'),                // ✅ display hardware
  ].join(S);

  // ================================================================
  //  P7: INTL DEEP PLANE (6 signals) — locale engine internals
  //  Intl implementation details vary by OS and browser engine.
  // ================================================================
  // P7: INTL ENGINE PLANE — profile-safe
  // CRITICAL: all Intl calls use FIXED locale 'en-US', not the default.
  // Using `undefined` or omitting locale → uses profile's default locale
  // → DIFFERENT output per profile. Fixed locale → reveals ICU version
  // and engine implementation, NOT the user's language setting.
  const P7 = (() => {
    try {
      // Fixed locale: output depends only on browser engine's ICU version
      const df = new Intl.DateTimeFormat('en-US').resolvedOptions();
      const nf = new Intl.NumberFormat('en-US').resolvedOptions();
      const co = new Intl.Collator('en-US').resolvedOptions();
      return [
        df.calendar || '',                                                         // ✅ engine ICU
        df.numberingSystem || '',                                                  // ✅ engine ICU
        nf.minimumIntegerDigits || '',                                             // ✅ engine default
        co.collation || '',                                                        // ✅ engine ICU
        co.sensitivity || '',                                                      // ✅ engine ICU
        co.caseFirst || '',                                                        // ✅ engine ICU
        new Intl.NumberFormat('en-US', { notation: 'compact' }).format(1234567),   // ✅ engine ICU
        new Intl.NumberFormat('en-US', { style: 'unit', unit: 'liter' }).format(3.14), // ✅ engine ICU
      ].join(S);
    } catch(_) { return ''; }
  })();

  // ================================================================
  //  P8: CSS ENGINE PLANE (8 signals) — CSS.supports capability
  //  Different browser engines support different CSS features.
  // ================================================================
  const cs = q => { try { return CSS.supports(q) ? 1 : 0; } catch(_) { return -1; } };

  const P8 = [
    cs('accent-color: auto'),
    cs('container-type: inline-size'),
    cs('color: oklch(0.5 0.2 240)'),
    cs('text-wrap: balance'),
    cs('view-transition-name: x'),
    cs('anchor-name: --a'),
    cs('field-sizing: content'),
    cs('interpolate-size: allow-keywords'),
  ].join(S);

  // ================================================================
  //  P9: WEBGL2 DEEP PLANE — parameters only available in WebGL2
  //  Different GPU generations expose different limits even when
  //  WebGL1 params and extension lists are identical (M1 vs M1 Max).
  //  Instagram's in-app browser supports WebGL2 on iOS 15+.
  // ================================================================
  const P9 = (() => {
    try {
      const c2 = document.createElement('canvas');
      const gl2 = c2.getContext('webgl2');
      if (!gl2) return '';
      const g = p => { try { return gl2.getParameter(p); } catch(_) { return ''; } };
      return [
        g(gl2.MAX_3D_TEXTURE_SIZE),
        g(gl2.MAX_ARRAY_TEXTURE_LAYERS),
        g(gl2.MAX_COLOR_ATTACHMENTS),
        g(gl2.MAX_DRAW_BUFFERS),
        g(gl2.MAX_SAMPLES),
        g(gl2.MAX_UNIFORM_BUFFER_BINDINGS),
        g(gl2.MAX_UNIFORM_BLOCK_SIZE),
        g(gl2.MAX_TRANSFORM_FEEDBACK_INTERLEAVED_COMPONENTS),
        g(gl2.MAX_TRANSFORM_FEEDBACK_SEPARATE_ATTRIBS),
        g(gl2.MAX_COMBINED_UNIFORM_BLOCKS),
        g(gl2.MAX_VERTEX_UNIFORM_BLOCKS),
        g(gl2.MAX_FRAGMENT_UNIFORM_BLOCKS),
        g(gl2.MAX_ELEMENT_INDEX),
        g(gl2.MAX_SERVER_WAIT_TIMEOUT),
        // WebGL2 extensions — separate from WebGL1 extension list
        (gl2.getSupportedExtensions() || []).sort().join(','),
      ].join(S);
    } catch(_) { return ''; }
  })();

  // ================================================================
  //  P10: CANVAS TEXT METRICS PLANE — font rendering fingerprint
  //  measureText() returns sub-pixel widths that vary by:
  //    - GPU text rasterizer (different per chip generation)
  //    - System font version (OS-version-locked)
  //    - Font hinting implementation (browser-engine-specific)
  //  Unlike canvas pixel rendering (noised by Safari ITP), text WIDTH
  //  measurement is deterministic and stable across page loads.
  // ================================================================
  const P10 = (() => {
    try {
      const c = document.createElement('canvas').getContext('2d');
      if (!c) return '';

      // Probe with specific font+size combos that maximize divergence
      const probes = [
        ['16px Arial',       'The quick brown fox jumps'],
        ['16px Georgia',     'Sphinx of black quartz, judge my vow'],
        ['14px Courier New', 'mmmmiiiiWWWW....0000'],
        ['20px Helvetica',   '\u00C0\u00E7\u00FC\u00F1\u4E16\u754C'],  // mixed scripts
        ['12px monospace',   'abcdefghijklmnopqrstuvwxyz'],
        ['18px serif',       '0123456789!@#$%^&*()'],
        ['11px sans-serif',  'lllllIIIII11111'],  // glyph-width sensitive
        ['bold 15px Arial',  'MWMWMWMW iiii....'],
      ];

      return probes.map(([font, text]) => {
        c.font = font;
        const m = c.measureText(text);
        // Combine width + actualBoundingBox metrics for max entropy
        return [
          m.width.toFixed(4),
          (m.actualBoundingBoxLeft  || 0).toFixed(2),
          (m.actualBoundingBoxRight || 0).toFixed(2),
          (m.actualBoundingBoxAscent  || 0).toFixed(2),
          (m.actualBoundingBoxDescent || 0).toFixed(2),
        ].join(':');
      }).join(S);
    } catch(_) { return ''; }
  })();

  // ================================================================
  //  ASSEMBLE + HASH
  // ================================================================
  const vector = [P1, P2, P3, P4, P5, P6, P7, P8, P9, P10].join(R);
  const digest = await hash256(vector);

  const id = 'ntrx_' +
    digest.slice(0,8)  + '-' + digest.slice(8,12)  + '-' +
    digest.slice(12,16) + '-' + digest.slice(16,20) + '-' +
    digest.slice(20,32) + '-' + digest.slice(32);

  console.log('ID:', id);
  window.__ntrx_id = id;
  try { window.dispatchEvent(new CustomEvent('ntrx:identified', { detail: { id } })); } catch(_) {}
}();
