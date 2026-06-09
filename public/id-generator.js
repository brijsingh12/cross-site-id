/**
 * Deterministic Device-Browser Fingerprint — Zero Storage Architecture
 * =====================================================================
 * Produces a stable 64-char hex ID from hardware-locked + browser-identity
 * signals only. NO storage (no cookies, localStorage, IndexedDB, cache).
 *
 * Guarantee matrix:
 *   Same browser, same device   → SAME ID   (deterministic)
 *   Same browser, different tab → SAME ID   (no state dependency)
 *   Different browser, same device → DIFFERENT ID (browser plane diverges)
 *   Different device            → DIFFERENT ID (hardware plane diverges)
 *
 * Signal architecture (4 orthogonal planes):
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │ Hardware Plane   — screen, cores, touch, memory, color     │
 *   │ GPU Plane        — renderer, vendor, texture limits, VP    │
 *   │ Browser Plane    — vendor string, engine globals, API caps │
 *   │ Engine Plane     — V8/JSC/SpiderMonkey math divergence     │
 *   └─────────────────────────────────────────────────────────────┘
 *
 * Excluded (unstable):
 *   canvas rendering (Safari ITP noise), audio fingerprint (varies),
 *   user-agent string (changes on update), fonts (app installs change),
 *   screen.availWidth/Height (dock/taskbar position changes it)
 *
 * Hash: SHA-256 via SubtleCrypto (async) with sync MurmurHash3 fallback.
 *
 * Usage:
 *   <script src="id-generator.js"></script>
 *   // Console: ID: ntrx_<64 hex chars>
 */
void async function NtrxFingerprint() {
  'use strict';

  // ================================================================
  //  SIGNAL COLLECTION — 4 orthogonal planes
  // ================================================================

  /**
   * Probe WebGL in a single canvas context creation.
   * Returns an object of GPU-locked constants, or an empty fallback.
   * These values are burned into the GPU driver and never change
   * between page loads.
   */
  const probeGPU = () => {
    try {
      const c  = document.createElement('canvas');
      const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return { r: '', v: '', mt: 0, mv: 0, mf: 0, mp: '', ml: '' };

      const dbg = gl.getExtension('WEBGL_debug_renderer_info');

      return {
        r:  gl.getParameter(dbg ? dbg.UNMASKED_RENDERER_WEBGL : gl.RENDERER),
        v:  gl.getParameter(dbg ? dbg.UNMASKED_VENDOR_WEBGL   : gl.VENDOR),
        mt: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        mv: gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS),
        mf: gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS),
        mp: String(Array.from(gl.getParameter(gl.MAX_VIEWPORT_DIMS) || [])),
        ml: String(Array.from(gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE) || []))
      };
    } catch (_) {
      return { r: '', v: '', mt: 0, mv: 0, mf: 0, mp: '', ml: '' };
    }
  };

  /**
   * JS engine math divergence probe.
   * V8, JavaScriptCore, and SpiderMonkey produce subtly different
   * results for transcendental functions at edge-case inputs.
   * The full-precision string representation captures these differences.
   *
   * Key insight: we concatenate at full precision (no toFixed rounding)
   * because the divergence is in the last 2-3 digits of the mantissa.
   */
  const probeEngine = () => [
    Math.cos(21),         // differs at bit 50+ between V8 and JSC
    Math.sinh(1),         // different reduction algorithms
    Math.atanh(0.5),      // polynomial approximation differs
    Math.expm1(1),        // compensation term varies by engine
    Math.cbrt(Math.PI),   // cube root algorithm differs
    Math.log1p(0.5),      // log1p implementation varies
    Math.tanh(2),         // hyperbolic range reduction
    (2 ** 53 + 1),        // integer overflow edge — reveals FP mode
  ].map(String).join('\x1F');  // unit separator — no collision with numeric strings

  /**
   * Browser identity plane.
   * These signals separate Chrome, Safari, Firefox, and Edge on the
   * SAME device without relying on the mutable User-Agent string.
   *
   * Trick: we probe for engine-specific globals and API shapes.
   * These are baked into the browser binary and never change between
   * page loads or across tabs.
   */
  const probeBrowser = () => {
    const w = window, n = navigator;
    return [
      n.vendor || '',                                         // "Google Inc." | "Apple Computer, Inc." | ""
      n.platform || '',                                       // "MacIntel" | "Win32" | ...
      typeof n.brave !== 'undefined' ? 1 : 0,                 // Brave shield
      typeof w.chrome !== 'undefined' ? 1 : 0,                // Chrome/Edge
      typeof w.safari !== 'undefined' ? 1 : 0,                // Safari
      typeof w.InstallTrigger !== 'undefined' ? 1 : 0,        // Firefox
      typeof n.userAgentData !== 'undefined' ? 1 : 0,         // Chrome 90+ UA-CH
      typeof w.SharedArrayBuffer !== 'undefined' ? 1 : 0,     // COOP/COEP capability
      typeof w.OffscreenCanvas !== 'undefined' ? 1 : 0,       // API availability
      typeof n.locks !== 'undefined' ? 1 : 0,                 // Web Locks API
      typeof w.ReportingObserver !== 'undefined' ? 1 : 0,     // Reporting API
      n.pdfViewerEnabled !== undefined ? Number(n.pdfViewerEnabled) : -1,
      n.cookieEnabled ? 1 : 0,
      n.languages ? n.languages.length : 0,                   // count, not values (stable)
    ].join('\x1F');
  };

  /**
   * Hardware plane — physical device constants.
   * These signals are locked to the display, CPU, and input hardware.
   * They are identical across all tabs, all sessions, all browser restarts.
   */
  const probeHardware = () => [
    screen.width,
    screen.height,
    screen.colorDepth,
    screen.pixelDepth,
    window.devicePixelRatio || 1,
    navigator.hardwareConcurrency || 0,
    navigator.maxTouchPoints || 0,
    navigator.deviceMemory || 0,                 // Chrome-only, 0 elsewhere
    Intl.DateTimeFormat().resolvedOptions().timeZone,
  ].join('\x1F');

  // ================================================================
  //  HASH — SHA-256 primary, MurmurHash3 × 8 fallback
  // ================================================================

  /**
   * Pre-computed hex lookup table (LUT).
   * Faster than byte.toString(16).padStart(2,'0') in a hot loop.
   * 256 entries × 2 chars = 512 bytes — fits in L1 cache.
   */
  const HEX_LUT = Array.from({ length: 256 }, (_, i) =>
    (i >>> 4).toString(16) + (i & 0xf).toString(16)
  );

  /** Convert ArrayBuffer to 64-char hex string using LUT. */
  const bufToHex = buf => {
    const u8 = new Uint8Array(buf);
    let hex = '';
    // Unrolled: process 4 bytes per iteration for ILP
    const len = u8.length;
    let i = 0;
    for (; i + 3 < len; i += 4) {
      hex += HEX_LUT[u8[i]] + HEX_LUT[u8[i+1]] + HEX_LUT[u8[i+2]] + HEX_LUT[u8[i+3]];
    }
    for (; i < len; i++) hex += HEX_LUT[u8[i]];
    return hex;
  };

  /**
   * MurmurHash3 (32-bit) — synchronous fallback.
   * Used only when SubtleCrypto is unavailable (non-HTTPS).
   *
   * Run 8 times with seeds 0-7 to produce 256 bits (64 hex chars).
   * Each run is O(n) on the input string; total is O(8n).
   *
   * @param {string} key  — input string
   * @param {number} seed — 32-bit seed
   * @returns {number}    — 32-bit unsigned hash
   */
  const murmur3_32 = (key, seed) => {
    let h = seed >>> 0;
    const len = key.length;
    const nblocks = len >> 2;

    // Body — process 4-byte blocks
    for (let i = 0; i < nblocks; i++) {
      let k = (key.charCodeAt(i * 4)      & 0xff)       |
              ((key.charCodeAt(i * 4 + 1) & 0xff) << 8)  |
              ((key.charCodeAt(i * 4 + 2) & 0xff) << 16) |
              ((key.charCodeAt(i * 4 + 3) & 0xff) << 24);
      k = Math.imul(k, 0xcc9e2d51);
      k = (k << 15) | (k >>> 17);
      k = Math.imul(k, 0x1b873593);
      h ^= k;
      h = (h << 13) | (h >>> 19);
      h = Math.imul(h, 5) + 0xe6546b64;
    }

    // Tail
    let k = 0;
    const tail = nblocks * 4;
    switch (len & 3) {
      case 3: k ^= (key.charCodeAt(tail + 2) & 0xff) << 16; // falls through
      case 2: k ^= (key.charCodeAt(tail + 1) & 0xff) << 8;  // falls through
      case 1: k ^= (key.charCodeAt(tail)     & 0xff);
              k  = Math.imul(k, 0xcc9e2d51);
              k  = (k << 15) | (k >>> 17);
              k  = Math.imul(k, 0x1b873593);
              h ^= k;
    }

    // Finalization mix (fmix32)
    h ^= len;
    h ^= h >>> 16;
    h  = Math.imul(h, 0x85ebca6b);
    h ^= h >>> 13;
    h  = Math.imul(h, 0xc2b2ae35);
    h ^= h >>> 16;

    return h >>> 0;
  };

  /**
   * Produce a 64-char hex hash from a string.
   * Primary: SHA-256 via SubtleCrypto (hardware-accelerated on most platforms).
   * Fallback: 8× MurmurHash3 with seeds 0-7 → 8×32 = 256 bits.
   */
  const hash256 = async (input) => {
    // Primary: SubtleCrypto SHA-256
    if (crypto?.subtle?.digest) {
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
      return bufToHex(buf);
    }

    // Fallback: 8× MurmurHash3 (synchronous)
    let hex = '';
    for (let seed = 0; seed < 8; seed++) {
      const h = murmur3_32(input, seed * 0x9e3779b9); // golden ratio spacing
      hex += HEX_LUT[h >>> 24] + HEX_LUT[(h >>> 16) & 0xff] +
             HEX_LUT[(h >>> 8) & 0xff] + HEX_LUT[h & 0xff];
    }
    return hex;
  };

  // ================================================================
  //  ORCHESTRATOR
  // ================================================================

  // Collect all 4 signal planes
  const gpu     = probeGPU();
  const engine  = probeEngine();
  const browser = probeBrowser();
  const hw      = probeHardware();

  // Assemble signal vector with plane separators (record separator 0x1E)
  // This prevents cross-plane value collision:
  //   e.g., hw="1440|900" + gpu="Apple" vs hw="1440" + gpu="900|Apple"
  const signalVector =
    hw                             + '\x1E' +  // hardware plane
    gpu.r + '\x1F' + gpu.v + '\x1F' +          // GPU identity
    gpu.mt + '\x1F' + gpu.mv + '\x1F' +
    gpu.mf + '\x1F' + gpu.mp + '\x1F' + gpu.ml + '\x1E' +
    browser                        + '\x1E' +  // browser identity plane
    engine;                                     // JS engine plane

  // Hash → 64-char hex
  const digest = await hash256(signalVector);

  // Format: ntrx_ prefix + 8-4-4-4-12 UUID-style grouping from the hash
  const id = 'ntrx_' +
    digest.slice(0, 8)  + '-' +
    digest.slice(8, 12) + '-' +
    digest.slice(12,16) + '-' +
    digest.slice(16,20) + '-' +
    digest.slice(20,32) + '-' +
    digest.slice(32);

  console.log('ID:', id);

  // Expose for programmatic access
  window.__ntrx_id = id;
  try {
    window.dispatchEvent(new CustomEvent('ntrx:identified', { detail: { id } }));
  } catch(_) {}

}();
