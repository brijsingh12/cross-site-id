#!/usr/bin/env node
'use strict';

/**
 * Collision Test Suite for NTRX Deterministic Fingerprint
 * ========================================================
 * Simulates thousands of device/browser/session combos and checks:
 *   1. Different entities MUST produce different IDs (no collisions)
 *   2. Same entity across tabs/sessions MUST produce the same ID (stability)
 *   3. Edge cases that could cause future collisions are flagged
 *
 * Run:  node test-collisions.js
 */

const crypto = require('crypto');

// ================================================================
//  SIGNAL SIMULATOR — mimics the 4 planes from id-generator.js
// ================================================================

/** Realistic hardware profiles drawn from real-world devices. */
const DEVICES = [
  // MacBooks
  { name: 'MacBook Air M1',       sw: 1440, sh: 900,  cd: 30, pd: 30, dpr: 2, hc: 8,  mtp: 0, dm: 0, gpu: 'Apple M1',                     gpuV: 'Apple',   mt: 16384, mv: 256, mf: 224, mp: '16384,16384', ml: '1,1' },
  { name: 'MacBook Air M2',       sw: 1470, sh: 956,  cd: 30, pd: 30, dpr: 2, hc: 8,  mtp: 0, dm: 0, gpu: 'Apple M2',                     gpuV: 'Apple',   mt: 16384, mv: 256, mf: 224, mp: '16384,16384', ml: '1,1' },
  { name: 'MacBook Pro 14 M2',    sw: 1512, sh: 982,  cd: 30, pd: 30, dpr: 2, hc: 8,  mtp: 0, dm: 0, gpu: 'Apple M2 Pro',                 gpuV: 'Apple',   mt: 16384, mv: 256, mf: 224, mp: '16384,16384', ml: '1,1' },
  { name: 'MacBook Pro 16 M2',    sw: 1728, sh: 1117, cd: 30, pd: 30, dpr: 2, hc: 12, mtp: 0, dm: 0, gpu: 'Apple M2 Max',                 gpuV: 'Apple',   mt: 16384, mv: 256, mf: 224, mp: '16384,16384', ml: '1,1' },
  { name: 'MacBook Pro 14 M3',    sw: 1512, sh: 982,  cd: 30, pd: 30, dpr: 2, hc: 8,  mtp: 0, dm: 0, gpu: 'Apple M3',                     gpuV: 'Apple',   mt: 16384, mv: 256, mf: 224, mp: '16384,16384', ml: '1,1' },
  { name: 'MacBook Pro 16 M3',    sw: 1728, sh: 1117, cd: 30, pd: 30, dpr: 2, hc: 12, mtp: 0, dm: 0, gpu: 'Apple M3 Pro',                 gpuV: 'Apple',   mt: 16384, mv: 256, mf: 224, mp: '16384,16384', ml: '1,1' },
  { name: 'MacBook Air M3',       sw: 1470, sh: 956,  cd: 30, pd: 30, dpr: 2, hc: 8,  mtp: 0, dm: 0, gpu: 'Apple M3',                     gpuV: 'Apple',   mt: 16384, mv: 256, mf: 224, mp: '16384,16384', ml: '1,1' },
  // iPhones
  { name: 'iPhone 15 Pro',        sw: 393,  sh: 852,  cd: 32, pd: 32, dpr: 3, hc: 6,  mtp: 5, dm: 0, gpu: 'Apple A17 Pro GPU',            gpuV: 'Apple',   mt: 16384, mv: 256, mf: 224, mp: '16384,16384', ml: '1,1' },
  { name: 'iPhone 14',            sw: 390,  sh: 844,  cd: 32, pd: 32, dpr: 3, hc: 6,  mtp: 5, dm: 0, gpu: 'Apple A15 GPU',                gpuV: 'Apple',   mt: 16384, mv: 256, mf: 224, mp: '16384,16384', ml: '1,1' },
  { name: 'iPhone 13',            sw: 390,  sh: 844,  cd: 32, pd: 32, dpr: 3, hc: 6,  mtp: 5, dm: 0, gpu: 'Apple A15 GPU',                gpuV: 'Apple',   mt: 16384, mv: 256, mf: 224, mp: '16384,16384', ml: '1,1' },
  { name: 'iPhone SE 3',          sw: 375,  sh: 667,  cd: 32, pd: 32, dpr: 2, hc: 6,  mtp: 5, dm: 0, gpu: 'Apple A15 GPU',                gpuV: 'Apple',   mt: 16384, mv: 256, mf: 224, mp: '16384,16384', ml: '1,1' },
  // iPads
  { name: 'iPad Pro 12.9 M2',     sw: 1024, sh: 1366, cd: 32, pd: 32, dpr: 2, hc: 8,  mtp: 5, dm: 0, gpu: 'Apple M2 GPU',                gpuV: 'Apple',   mt: 16384, mv: 256, mf: 224, mp: '16384,16384', ml: '1,1' },
  { name: 'iPad Air M1',          sw: 820,  sh: 1180, cd: 32, pd: 32, dpr: 2, hc: 8,  mtp: 5, dm: 0, gpu: 'Apple M1 GPU',                gpuV: 'Apple',   mt: 16384, mv: 256, mf: 224, mp: '16384,16384', ml: '1,1' },
  // Windows laptops
  { name: 'Dell XPS 15',          sw: 1920, sh: 1200, cd: 24, pd: 24, dpr: 1.25, hc: 12, mtp: 0, dm: 8, gpu: 'ANGLE (NVIDIA, RTX 3050 Ti)', gpuV: 'Google Inc. (NVIDIA)', mt: 16384, mv: 4096, mf: 1024, mp: '32768,32768', ml: '1,7.375' },
  { name: 'ThinkPad X1 Carbon',   sw: 1920, sh: 1080, cd: 24, pd: 24, dpr: 1,    hc: 8,  mtp: 0, dm: 8, gpu: 'ANGLE (Intel, Iris Xe)',     gpuV: 'Google Inc. (Intel)',  mt: 16384, mv: 4096, mf: 1024, mp: '32768,32768', ml: '1,7.375' },
  { name: 'HP Spectre x360',      sw: 1920, sh: 1080, cd: 24, pd: 24, dpr: 1.5,  hc: 8,  mtp: 10,dm: 8, gpu: 'ANGLE (Intel, Iris Xe)',     gpuV: 'Google Inc. (Intel)',  mt: 16384, mv: 4096, mf: 1024, mp: '32768,32768', ml: '1,7.375' },
  { name: 'Surface Pro 9',        sw: 2880, sh: 1920, cd: 24, pd: 24, dpr: 2,    hc: 12, mtp: 10,dm: 8, gpu: 'ANGLE (Intel, Iris Xe)',     gpuV: 'Google Inc. (Intel)',  mt: 16384, mv: 4096, mf: 1024, mp: '32768,32768', ml: '1,7.375' },
  // Samsung phones
  { name: 'Galaxy S24 Ultra',     sw: 384,  sh: 824,  cd: 24, pd: 24, dpr: 3.75, hc: 8,  mtp: 5, dm: 8, gpu: 'Adreno (TM) 750',           gpuV: 'Qualcomm', mt: 16384, mv: 256, mf: 224, mp: '16384,16384', ml: '1,1' },
  { name: 'Galaxy S23',           sw: 360,  sh: 780,  cd: 24, pd: 24, dpr: 3,    hc: 8,  mtp: 5, dm: 8, gpu: 'Adreno (TM) 740',           gpuV: 'Qualcomm', mt: 16384, mv: 256, mf: 224, mp: '16384,16384', ml: '1,1' },
  // Linux
  { name: 'Linux Desktop',        sw: 2560, sh: 1440, cd: 24, pd: 24, dpr: 1,    hc: 16, mtp: 0, dm: 0, gpu: 'Mesa Intel(R) UHD 770',     gpuV: 'Intel',   mt: 16384, mv: 4096, mf: 1024, mp: '32768,32768', ml: '1,7.375' },
];

/** Browser profiles with engine-specific signal differences. */
const BROWSERS = [
  {
    name: 'Chrome',
    vendor: 'Google Inc.',
    platform_mac: 'MacIntel', platform_win: 'Win32', platform_linux: 'Linux x86_64', platform_ios: 'iPhone', platform_android: 'Linux armv8l',
    chrome: 1, safari: 0, firefox: 0, brave: 0, uaData: 1,
    sharedArrayBuffer: 1, offscreenCanvas: 1, locks: 1, reportingObserver: 1, pdfViewer: 1, cookieEnabled: 1, langCount: 3,
    // V8 engine math results
    math: ['-0.5477292602242684', '1.1752011936438014', '0.5493061443340548', '1.718281828459045', '1.4645918875615231', '0.4054651081081644', '0.9640275800758169', '9007199254740992'],
    // Chrome reports GPU via ANGLE
    gpuPrefix: 'ANGLE (',
  },
  {
    name: 'Safari',
    vendor: 'Apple Computer, Inc.',
    platform_mac: 'MacIntel', platform_ios: 'iPhone', platform_ipad: 'iPad',
    chrome: 0, safari: 1, firefox: 0, brave: 0, uaData: 0,
    sharedArrayBuffer: 1, offscreenCanvas: 1, locks: 1, reportingObserver: 0, pdfViewer: 1, cookieEnabled: 1, langCount: 2,
    // JavaScriptCore math results (differ at last digits)
    math: ['-0.5477292602242684', '1.1752011936438014', '0.5493061443340549', '1.7182818284590453', '1.4645918875615232', '0.40546510810816444', '0.9640275800758168', '9007199254740992'],
    // Safari reports generic GPU name
    gpuPrefix: '',
  },
  {
    name: 'Firefox',
    vendor: '',
    platform_mac: 'MacIntel', platform_win: 'Win32', platform_linux: 'Linux x86_64',
    chrome: 0, safari: 0, firefox: 1, brave: 0, uaData: 0,
    sharedArrayBuffer: 1, offscreenCanvas: 1, locks: 1, reportingObserver: 0, pdfViewer: 1, cookieEnabled: 1, langCount: 2,
    // SpiderMonkey math results
    math: ['-0.5477292602242684', '1.1752011936438014', '0.5493061443340548', '1.718281828459045', '1.4645918875615231', '0.4054651081081644', '0.9640275800758169', '9007199254740992'],
    gpuPrefix: '',
  },
  {
    name: 'Edge',
    vendor: 'Google Inc.',
    platform_mac: 'MacIntel', platform_win: 'Win32',
    chrome: 1, safari: 0, firefox: 0, brave: 0, uaData: 1,
    sharedArrayBuffer: 1, offscreenCanvas: 1, locks: 1, reportingObserver: 1, pdfViewer: 1, cookieEnabled: 1, langCount: 3,
    // Edge uses V8 (same as Chrome)
    math: ['-0.5477292602242684', '1.1752011936438014', '0.5493061443340548', '1.718281828459045', '1.4645918875615231', '0.4054651081081644', '0.9640275800758169', '9007199254740992'],
    gpuPrefix: 'ANGLE (',
  },
  {
    name: 'Instagram Browser',
    vendor: 'Apple Computer, Inc.',
    platform_ios: 'iPhone',
    chrome: 0, safari: 1, firefox: 0, brave: 0, uaData: 0,
    sharedArrayBuffer: 0, offscreenCanvas: 0, locks: 1, reportingObserver: 0, pdfViewer: 0, cookieEnabled: 1, langCount: 1,
    math: ['-0.5477292602242684', '1.1752011936438014', '0.5493061443340549', '1.7182818284590453', '1.4645918875615232', '0.40546510810816444', '0.9640275800758168', '9007199254740992'],
    gpuPrefix: '',
  },
  {
    name: 'Brave',
    vendor: 'Google Inc.',
    platform_mac: 'MacIntel', platform_win: 'Win32',
    chrome: 1, safari: 0, firefox: 0, brave: 1, uaData: 1,
    sharedArrayBuffer: 1, offscreenCanvas: 1, locks: 1, reportingObserver: 1, pdfViewer: 1, cookieEnabled: 1, langCount: 2,
    math: ['-0.5477292602242684', '1.1752011936438014', '0.5493061443340548', '1.718281828459045', '1.4645918875615231', '0.4054651081081644', '0.9640275800758169', '9007199254740992'],
    gpuPrefix: 'ANGLE (',
  },
];

const TIMEZONES = [
  'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
  'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Asia/Tokyo',
  'Asia/Shanghai', 'Asia/Kolkata', 'Asia/Dubai', 'Australia/Sydney',
  'Pacific/Auckland', 'America/Sao_Paulo', 'Africa/Lagos'
];

// ================================================================
//  SIGNAL VECTOR BUILDER — replicates id-generator.js logic exactly
// ================================================================

function buildSignalVector(device, browser, timezone) {
  // Determine platform
  let platform;
  if (device.name.includes('iPhone') || device.name.includes('Galaxy S')) {
    platform = browser.platform_ios || browser.platform_android || 'Linux armv8l';
  } else if (device.name.includes('iPad')) {
    platform = browser.platform_ipad || browser.platform_ios || 'iPad';
  } else if (device.name.includes('Linux')) {
    platform = browser.platform_linux || 'Linux x86_64';
  } else if (device.name.includes('Dell') || device.name.includes('ThinkPad') || device.name.includes('HP') || device.name.includes('Surface')) {
    platform = browser.platform_win || 'Win32';
  } else {
    platform = browser.platform_mac || 'MacIntel';
  }

  // GPU name — Chrome uses ANGLE prefix, Safari uses raw name
  const gpuName = browser.gpuPrefix
    ? browser.gpuPrefix + device.gpuV + ', ' + device.gpu + ')'
    : device.gpu;

  // Hardware plane
  const hw = [
    device.sw, device.sh, device.cd, device.pd,
    device.dpr, device.hc, device.mtp, device.dm, timezone
  ].join('\x1F');

  // GPU plane
  const gpuPlane = [
    gpuName, device.gpuV,
    device.mt, device.mv, device.mf, device.mp, device.ml
  ].join('\x1F');

  // Browser plane
  const browserPlane = [
    browser.vendor, platform,
    browser.brave, browser.chrome, browser.safari, browser.firefox,
    browser.uaData, browser.sharedArrayBuffer, browser.offscreenCanvas,
    browser.locks, browser.reportingObserver, browser.pdfViewer,
    browser.cookieEnabled, browser.langCount
  ].join('\x1F');

  // Engine plane
  const enginePlane = browser.math.join('\x1F');

  return hw + '\x1E' + gpuPlane + '\x1E' + browserPlane + '\x1E' + enginePlane;
}

function hashSHA256(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function buildId(signalVector) {
  const digest = hashSHA256(signalVector);
  return 'ntrx_' +
    digest.slice(0, 8)  + '-' + digest.slice(8, 12) + '-' +
    digest.slice(12,16) + '-' + digest.slice(16,20) + '-' +
    digest.slice(20,32) + '-' + digest.slice(32);
}

// ================================================================
//  TEST RUNNERS
// ================================================================

function randomPick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function randomInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

const results = {
  totalTests: 0,
  uniqueIds: new Map(),      // id → { device, browser, timezone, vector }
  collisions: [],
  stabilityFailures: [],
};

/** Test 1: Different entities must produce different IDs. */
function testUniqueness(count) {
  console.log(`\n${'═'.repeat(70)}`);
  console.log('  TEST 1: UNIQUENESS — different entities → different IDs');
  console.log(`${'═'.repeat(70)}`);

  for (let i = 0; i < count; i++) {
    const device   = randomPick(DEVICES);
    const browser  = randomPick(BROWSERS);
    const timezone = randomPick(TIMEZONES);

    const vector = buildSignalVector(device, browser, timezone);
    const id     = buildId(vector);

    results.totalTests++;

    const existing = results.uniqueIds.get(id);
    if (existing) {
      // Check if it's actually the same entity (valid duplicate) or a collision
      if (existing.device !== device.name || existing.browser !== browser.name || existing.timezone !== timezone) {
        results.collisions.push({
          id,
          entity1: { device: existing.device, browser: existing.browser, timezone: existing.timezone },
          entity2: { device: device.name, browser: browser.name, timezone: timezone },
          vector1: existing.vector,
          vector2: vector,
        });
      }
      // else: same entity regenerated same ID — correct behavior
    } else {
      results.uniqueIds.set(id, { device: device.name, browser: browser.name, timezone, vector });
    }
  }
}

/** Test 2: Exhaustive cross-product of all devices × browsers × timezones. */
function testExhaustiveCrossProduct() {
  console.log(`\n${'═'.repeat(70)}`);
  console.log('  TEST 2: EXHAUSTIVE CROSS-PRODUCT — all combos must be unique');
  console.log(`${'═'.repeat(70)}`);

  const seen = new Map();
  let tests = 0;
  let collisions = 0;

  for (const device of DEVICES) {
    for (const browser of BROWSERS) {
      // Skip impossible combos (e.g., Firefox on iPhone)
      if (device.name.includes('iPhone') && browser.name === 'Firefox') continue;
      if (device.name.includes('iPad') && browser.name === 'Firefox') continue;
      if (device.name.includes('Galaxy') && browser.name === 'Safari') continue;
      if (device.name.includes('Galaxy') && browser.name === 'Instagram Browser') continue;
      if (device.name.includes('Linux') && browser.name === 'Safari') continue;
      if (device.name.includes('Linux') && browser.name === 'Instagram Browser') continue;

      for (const tz of TIMEZONES) {
        const vector = buildSignalVector(device, browser, tz);
        const id = buildId(vector);
        tests++;
        results.totalTests++;

        const key = `${device.name}|${browser.name}|${tz}`;
        const existing = seen.get(id);

        if (existing && existing !== key) {
          collisions++;
          results.collisions.push({
            id,
            entity1: { combo: existing },
            entity2: { combo: key },
          });
        } else {
          seen.set(id, key);
        }
      }
    }
  }

  console.log(`  Combos tested: ${tests}`);
  console.log(`  Unique IDs:    ${seen.size}`);
  console.log(`  Collisions:    ${collisions}`);
}

/** Test 3: Stability — same entity must produce same ID every time. */
function testStability(iterations) {
  console.log(`\n${'═'.repeat(70)}`);
  console.log('  TEST 3: STABILITY — same entity across tabs/sessions → same ID');
  console.log(`${'═'.repeat(70)}`);

  let tests = 0;
  let failures = 0;

  for (const device of DEVICES.slice(0, 8)) {
    for (const browser of BROWSERS.slice(0, 4)) {
      const tz = 'America/New_York';
      const baseVector = buildSignalVector(device, browser, tz);
      const baseId = buildId(baseVector);

      // Simulate N "reloads" — should always produce the same vector and ID
      for (let i = 0; i < iterations; i++) {
        const reloadVector = buildSignalVector(device, browser, tz);
        const reloadId = buildId(reloadVector);
        tests++;
        results.totalTests++;

        if (reloadId !== baseId) {
          failures++;
          results.stabilityFailures.push({
            device: device.name,
            browser: browser.name,
            baseId,
            reloadId,
            diff: diffVectors(baseVector, reloadVector),
          });
        }
      }
    }
  }

  console.log(`  Stability tests: ${tests}`);
  console.log(`  Failures:        ${failures}`);
}

/** Test 4: Near-miss analysis — find the closest ID pairs (birthday attack surface). */
function testNearMiss() {
  console.log(`\n${'═'.repeat(70)}`);
  console.log('  TEST 4: NEAR-MISS ANALYSIS — closest ID pairs');
  console.log(`${'═'.repeat(70)}`);

  const ids = [...results.uniqueIds.entries()].slice(0, 500);
  let minDist = Infinity;
  let closestPair = null;

  // Compare hex prefix distances (first 16 chars = 64 bits)
  for (let i = 0; i < ids.length; i++) {
    for (let j = i + 1; j < ids.length; j++) {
      const a = ids[i][0].replace(/ntrx_|-/g, '');
      const b = ids[j][0].replace(/ntrx_|-/g, '');
      const dist = hammingDistHex(a, b);
      if (dist < minDist) {
        minDist = dist;
        closestPair = [ids[i], ids[j]];
      }
    }
  }

  if (closestPair) {
    console.log(`  Minimum hamming distance: ${minDist} / 256 bits`);
    console.log(`  Pair A: ${closestPair[0][1].device} + ${closestPair[0][1].browser}`);
    console.log(`  Pair B: ${closestPair[1][1].device} + ${closestPair[1][1].browser}`);
    console.log(`  ID A:   ${closestPair[0][0]}`);
    console.log(`  ID B:   ${closestPair[1][0]}`);
    console.log(`  (SHA-256 avalanche: any bit flip should change ~50% of output bits)`);
    console.log(`  (Expected min distance for ${ids.length} IDs: ~${Math.floor(256 - Math.log2(ids.length) * 2)} bits)`);
  }
}

/** Test 5: Edge case collision scenarios. */
function testEdgeCases() {
  console.log(`\n${'═'.repeat(70)}`);
  console.log('  TEST 5: EDGE CASE ANALYSIS — scenarios that COULD collide');
  console.log(`${'═'.repeat(70)}`);

  const edgeCases = [
    {
      name: 'Two identical MacBook Air M2 — same browser, same timezone',
      desc: 'Same model laptop, same browser, same location. Fingerprints would be identical.',
      risk: 'CRITICAL',
      mitigated: 'NO — identical hardware + same browser = identical signals = SAME ID',
      note: 'This is BY DESIGN for the zero-storage architecture. There is no way to differentiate identical setups without storage.',
    },
    {
      name: 'iPhone 14 vs iPhone 13 — Safari, same timezone',
      desc: 'Same screen resolution (390×844) but different GPU (A15 vs A15). Both report "Apple GPU" in Safari.',
      risk: 'HIGH',
      test: () => {
        const v1 = buildSignalVector(DEVICES.find(d => d.name === 'iPhone 14'), BROWSERS.find(b => b.name === 'Safari'), 'Asia/Kolkata');
        const v2 = buildSignalVector(DEVICES.find(d => d.name === 'iPhone 13'), BROWSERS.find(b => b.name === 'Safari'), 'Asia/Kolkata');
        return { collides: buildId(v1) === buildId(v2), id1: buildId(v1), id2: buildId(v2) };
      },
    },
    {
      name: 'Chrome vs Edge — same device (both V8, both "Google Inc.")',
      desc: 'Chrome and Edge share V8 engine and navigator.vendor. The userAgentData and browser globals probe should differentiate them.',
      risk: 'MEDIUM',
      test: () => {
        const device = DEVICES[0]; // MacBook Air M1
        const v1 = buildSignalVector(device, BROWSERS.find(b => b.name === 'Chrome'), 'America/New_York');
        const v2 = buildSignalVector(device, BROWSERS.find(b => b.name === 'Edge'), 'America/New_York');
        return { collides: buildId(v1) === buildId(v2), id1: buildId(v1), id2: buildId(v2) };
      },
    },
    {
      name: 'Safari vs Instagram browser — same iPhone',
      desc: 'Both use JavaScriptCore, both report "Apple Computer, Inc." The API capability probes (SharedArrayBuffer, OffscreenCanvas) should differ.',
      risk: 'MEDIUM',
      test: () => {
        const device = DEVICES.find(d => d.name === 'iPhone 15 Pro');
        const v1 = buildSignalVector(device, BROWSERS.find(b => b.name === 'Safari'), 'Asia/Kolkata');
        const v2 = buildSignalVector(device, BROWSERS.find(b => b.name === 'Instagram Browser'), 'Asia/Kolkata');
        return { collides: buildId(v1) === buildId(v2), id1: buildId(v1), id2: buildId(v2) };
      },
    },
    {
      name: 'User changes timezone (travel)',
      desc: 'Same device, same browser, but user flies from NYC to London. Timezone signal changes → different ID.',
      risk: 'LOW',
      note: 'Timezone is included for entropy. Removing it reduces collision resistance but improves travel stability. Trade-off decision.',
      test: () => {
        const device = DEVICES[0];
        const browser = BROWSERS[0];
        const v1 = buildSignalVector(device, browser, 'America/New_York');
        const v2 = buildSignalVector(device, browser, 'Europe/London');
        return { collides: buildId(v1) === buildId(v2), id1: buildId(v1), id2: buildId(v2) };
      },
    },
    {
      name: 'External monitor changes resolution',
      desc: 'Laptop plugged into external monitor changes screen.width/height → different ID.',
      risk: 'LOW',
      note: 'Hardware-locked signal. ID changes when display config changes. Acceptable trade-off for collision resistance.',
    },
    {
      name: 'Browser update changes WebGL renderer string',
      desc: 'Chrome updates ANGLE version → WebGL renderer string changes → different ID.',
      risk: 'LOW',
      note: 'Rare. ANGLE version is not included in the renderer string on most platforms.',
    },
    {
      name: 'WebGL disabled / no GPU',
      desc: 'Two different devices with WebGL disabled would fall back to empty GPU signals → rely only on hardware + browser + engine planes.',
      risk: 'MEDIUM',
      note: 'GPU plane provides significant entropy. Without it, collision space is smaller.',
      test: () => {
        const d1 = { ...DEVICES[0], gpu: '', gpuV: '', mt: 0, mv: 0, mf: 0, mp: '', ml: '' };
        const d2 = { ...DEVICES[1], gpu: '', gpuV: '', mt: 0, mv: 0, mf: 0, mp: '', ml: '' };
        const v1 = buildSignalVector(d1, BROWSERS[0], 'America/New_York');
        const v2 = buildSignalVector(d2, BROWSERS[0], 'America/New_York');
        return { collides: buildId(v1) === buildId(v2), id1: buildId(v1), id2: buildId(v2) };
      },
    },
  ];

  for (const ec of edgeCases) {
    console.log(`\n  ┌─ ${ec.name}`);
    console.log(`  │  Risk: ${ec.risk}`);
    console.log(`  │  ${ec.desc}`);
    if (ec.note) console.log(`  │  Note: ${ec.note}`);
    if (ec.mitigated) console.log(`  │  Mitigated: ${ec.mitigated}`);
    if (ec.test) {
      const r = ec.test();
      results.totalTests++;
      const status = r.collides ? '⚠ COLLISION' : '✓ SAFE';
      console.log(`  │  Result: ${status}`);
      if (r.collides) {
        console.log(`  │  ID: ${r.id1}`);
        results.collisions.push({ id: r.id1, edgeCase: ec.name });
      }
    }
    console.log(`  └${'─'.repeat(68)}`);
  }
}

/** Test 6: Randomized fuzzing — perturb single signals to check sensitivity. */
function testFuzzing(count) {
  console.log(`\n${'═'.repeat(70)}`);
  console.log('  TEST 6: SIGNAL SENSITIVITY FUZZ — single signal perturbation');
  console.log(`${'═'.repeat(70)}`);

  const baseDevice  = DEVICES[0];
  const baseBrowser = BROWSERS[0];
  const baseTZ      = 'America/New_York';
  const baseVector  = buildSignalVector(baseDevice, baseBrowser, baseTZ);
  const baseId      = buildId(baseVector);

  const perturbations = [
    { name: 'screen.width +1',        fn: d => ({ ...d, sw: d.sw + 1 }) },
    { name: 'screen.height +1',       fn: d => ({ ...d, sh: d.sh + 1 }) },
    { name: 'colorDepth 24→30',       fn: d => ({ ...d, cd: 30, pd: 30 }) },
    { name: 'dpr 2→2.5',              fn: d => ({ ...d, dpr: 2.5 }) },
    { name: 'cores 8→10',             fn: d => ({ ...d, hc: 10 }) },
    { name: 'touchPoints 0→5',        fn: d => ({ ...d, mtp: 5 }) },
    { name: 'deviceMemory 0→8',       fn: d => ({ ...d, dm: 8 }) },
    { name: 'GPU renderer slight change', fn: d => ({ ...d, gpu: d.gpu + ' (v2)' }) },
  ];

  let allDiff = true;
  for (const p of perturbations) {
    const perturbedDevice = p.fn({ ...baseDevice });
    const pVector = buildSignalVector(perturbedDevice, baseBrowser, baseTZ);
    const pId = buildId(pVector);
    results.totalTests++;
    const changed = pId !== baseId;
    if (!changed) allDiff = false;
    console.log(`  ${changed ? '✓' : '⚠'} ${p.name.padEnd(35)} → ID ${changed ? 'CHANGED' : 'SAME (COLLISION!)'}`);
  }

  console.log(`\n  Sensitivity: ${allDiff ? 'ALL perturbations produce unique IDs ✓' : '⚠ Some perturbations did NOT change the ID'}`);
}

// ================================================================
//  UTILITY
// ================================================================

function hammingDistHex(a, b) {
  let dist = 0;
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const xor = parseInt(a[i], 16) ^ parseInt(b[i], 16);
    dist += popcount4(xor);
  }
  return dist;
}

function popcount4(n) {
  n = n - ((n >> 1) & 5);
  n = (n & 3) + ((n >> 2) & 3);
  return n;
}

function diffVectors(a, b) {
  const aP = a.split('\x1E');
  const bP = b.split('\x1E');
  const planes = ['hardware', 'gpu', 'browser', 'engine'];
  const diffs = [];
  for (let i = 0; i < planes.length; i++) {
    if (aP[i] !== bP[i]) diffs.push(planes[i]);
  }
  return diffs;
}

// ================================================================
//  MAIN — run all tests and print report
// ================================================================

console.log('╔══════════════════════════════════════════════════════════════════════╗');
console.log('║    NTRX Fingerprint Collision Test Suite                            ║');
console.log('║    Deterministic Device-Browser ID — Zero Storage Architecture     ║');
console.log('╚══════════════════════════════════════════════════════════════════════╝');
console.log(`\n  Devices:   ${DEVICES.length}`);
console.log(`  Browsers:  ${BROWSERS.length}`);
console.log(`  Timezones: ${TIMEZONES.length}`);
console.log(`  Max combos: ${DEVICES.length * BROWSERS.length * TIMEZONES.length}`);

testUniqueness(50000);
testExhaustiveCrossProduct();
testStability(100);
testNearMiss();
testEdgeCases();
testFuzzing(100);

// ================================================================
//  FINAL REPORT
// ================================================================

console.log(`\n${'═'.repeat(70)}`);
console.log('  FINAL REPORT');
console.log(`${'═'.repeat(70)}`);
console.log(`  Total tests run:       ${results.totalTests.toLocaleString()}`);
console.log(`  Unique IDs generated:  ${results.uniqueIds.size.toLocaleString()}`);
console.log(`  Collisions detected:   ${results.collisions.length}`);
console.log(`  Stability failures:    ${results.stabilityFailures.length}`);
console.log(`  Collision rate:        ${(results.collisions.length / results.totalTests * 100).toFixed(6)}%`);

if (results.collisions.length > 0) {
  console.log(`\n  ⚠ COLLISION DETAILS:`);
  for (const c of results.collisions) {
    console.log(`\n    ID: ${c.id}`);
    if (c.edgeCase) {
      console.log(`    Edge case: ${c.edgeCase}`);
    } else {
      console.log(`    Entity 1: ${JSON.stringify(c.entity1)}`);
      console.log(`    Entity 2: ${JSON.stringify(c.entity2)}`);
    }
  }
}

if (results.stabilityFailures.length > 0) {
  console.log(`\n  ⚠ STABILITY FAILURE DETAILS:`);
  for (const f of results.stabilityFailures) {
    console.log(`    ${f.device} + ${f.browser}: base=${f.baseId} ≠ reload=${f.reloadId}`);
    console.log(`    Differing planes: ${f.diff.join(', ')}`);
  }
}

console.log(`\n${'═'.repeat(70)}`);
console.log('  KNOWN LIMITATIONS (by design):');
console.log(`${'═'.repeat(70)}`);
console.log('  1. IDENTICAL HARDWARE + SAME BROWSER + SAME TIMEZONE = SAME ID');
console.log('     This is inherent to zero-storage fingerprinting. Two identical');
console.log('     MacBook Airs with the same browser and timezone cannot be');
console.log('     distinguished without storage.');
console.log('');
console.log('  2. TIMEZONE CHANGE = ID CHANGE');
console.log('     Traveling across timezones changes the ID. Remove timezone');
console.log('     from the signal vector to fix, at the cost of reduced entropy.');
console.log('');
console.log('  3. EXTERNAL MONITOR = ID CHANGE');
console.log('     Plugging in a different display changes screen resolution signals.');
console.log('');
console.log('  4. CHROME AND EDGE SHARE V8 ENGINE');
console.log('     They are differentiated by browser-specific globals and API');
console.log('     capabilities, not math results. If both had identical API');
console.log('     surfaces, they would collide on the same device.');
console.log(`${'═'.repeat(70)}\n`);
