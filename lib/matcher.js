'use strict';

/**
 * Identity Matcher — ML-inspired weighted similarity scoring engine.
 *
 * Uses 7 signal categories with independent weights to compute a
 * confidence score for identity matching. Each category contributes
 * a normalised 0-1 similarity, and the final score is the weighted
 * sum. A match is only accepted above the CONFIDENCE_THRESHOLD.
 *
 * Signal categories and weights:
 *   1. IP Intelligence    (0.12) — subnet, ASN
 *   2. Browser FP         (0.20) — canvas hash, WebGL, audio, math, fonts
 *   3. Device Intelligence(0.15) — GPU, screen, hardware, OS, browser
 *   4. Behavioral Signals (0.18) — mouse velocity, scroll, interaction timing
 *   5. Header FP          (0.10) — Accept, Accept-Language, Accept-Encoding order
 *   6. Timezone/Locale    (0.10) — tz, locale formats, languages
 *   7. Historical Pattern (0.15) — time-of-day, visit frequency, site pattern
 */

const CONFIDENCE_THRESHOLD = 0.82;  // high threshold to prevent collisions

const CATEGORY_WEIGHTS = {
  ip:         0.12,
  fingerprint:0.20,
  device:     0.15,
  behavior:   0.18,
  headers:    0.10,
  locale:     0.10,
  history:    0.15
};

/**
 * Compare two profiles and return { score, breakdown }.
 * @param {Object} candidate — stored profile
 * @param {Object} probe     — incoming signals
 * @returns {{ score: number, breakdown: Object, match: boolean }}
 */
function compareProfiles(candidate, probe) {
  const breakdown = {};

  // 1. IP Intelligence
  breakdown.ip = scoreIP(candidate.ip, probe.ip);

  // 2. Browser Fingerprint
  breakdown.fingerprint = scoreFingerprint(candidate.fingerprint, probe.fingerprint);

  // 3. Device Intelligence
  breakdown.device = scoreDevice(candidate.device, probe.device);

  // 4. Behavioral Signals
  breakdown.behavior = scoreBehavior(candidate.behavior, probe.behavior);

  // 5. Header Fingerprint
  breakdown.headers = scoreHeaders(candidate.headers, probe.headers);

  // 6. Timezone / Locale
  breakdown.locale = scoreLocale(candidate.locale, probe.locale);

  // 7. Historical Pattern
  breakdown.history = scoreHistory(candidate.history, probe.history);

  // Weighted sum
  let score = 0;
  for (const [cat, weight] of Object.entries(CATEGORY_WEIGHTS)) {
    score += (breakdown[cat] || 0) * weight;
  }

  return {
    score: Math.round(score * 1000) / 1000,
    breakdown,
    match: score >= CONFIDENCE_THRESHOLD
  };
}

// ================================================================
//  SCORING FUNCTIONS — each returns 0.0 to 1.0
// ================================================================

function scoreIP(a, b) {
  if (!a || !b) return 0.5; // no data = neutral
  let s = 0;
  // Same exact IP
  if (a.ip && b.ip && a.ip === b.ip) s += 0.4;
  // Same /24 subnet
  if (a.subnet && b.subnet && a.subnet === b.subnet) s += 0.35;
  else if (a.ip && b.ip) {
    // Check if first 3 octets match (simple /24)
    const a3 = a.ip.split('.').slice(0, 3).join('.');
    const b3 = b.ip.split('.').slice(0, 3).join('.');
    if (a3 === b3) s += 0.25;
  }
  // Same ASN
  if (a.asn && b.asn && a.asn === b.asn) s += 0.25;
  return Math.min(s, 1.0);
}

function scoreFingerprint(a, b) {
  if (!a || !b) return 0;
  const fields = [
    ['canvasHash', 2], ['webglRenderer', 3], ['webglVendor', 2],
    ['audioHash', 2], ['mathHash', 2], ['fontsHash', 3]
  ];
  return weightedFieldMatch(a, b, fields);
}

function scoreDevice(a, b) {
  if (!a || !b) return 0;
  const fields = [
    ['gpu', 3], ['screenW', 1], ['screenH', 1], ['dpr', 1],
    ['colorDepth', 1], ['hardwareConcurrency', 2], ['maxTouchPoints', 2],
    ['deviceMemory', 1], ['platform', 2], ['availW', 1], ['availH', 1]
  ];
  return weightedFieldMatch(a, b, fields);
}

function scoreBehavior(a, b) {
  if (!a || !b) return 0.5; // no data = neutral (don't penalise)
  if (!a.mouseSpeed && !b.mouseSpeed) return 0.5;

  let s = 0, total = 0;

  // Mouse speed similarity (within 30% = match)
  if (a.mouseSpeed && b.mouseSpeed) {
    total += 3;
    const ratio = Math.min(a.mouseSpeed, b.mouseSpeed) / Math.max(a.mouseSpeed, b.mouseSpeed);
    s += ratio > 0.7 ? 3 * ratio : 0;
  }

  // Scroll speed
  if (a.scrollSpeed && b.scrollSpeed) {
    total += 2;
    const ratio = Math.min(a.scrollSpeed, b.scrollSpeed) / Math.max(a.scrollSpeed, b.scrollSpeed);
    s += ratio > 0.6 ? 2 * ratio : 0;
  }

  // Interaction timing bucket (fast/medium/slow user)
  if (a.interactionBucket && b.interactionBucket) {
    total += 2;
    if (a.interactionBucket === b.interactionBucket) s += 2;
  }

  return total > 0 ? s / total : 0.5;
}

function scoreHeaders(a, b) {
  if (!a || !b) return 0.5;
  let s = 0;
  if (a.acceptLanguage && b.acceptLanguage && a.acceptLanguage === b.acceptLanguage) s += 0.4;
  if (a.acceptEncoding && b.acceptEncoding && a.acceptEncoding === b.acceptEncoding) s += 0.3;
  if (a.accept && b.accept && a.accept === b.accept) s += 0.3;
  return s;
}

function scoreLocale(a, b) {
  if (!a || !b) return 0.5;
  let s = 0;
  if (a.timezone && b.timezone && a.timezone === b.timezone) s += 0.4;
  if (a.languages && b.languages && a.languages === b.languages) s += 0.3;
  if (a.dateFormat && b.dateFormat && a.dateFormat === b.dateFormat) s += 0.15;
  if (a.numberFormat && b.numberFormat && a.numberFormat === b.numberFormat) s += 0.15;
  return s;
}

function scoreHistory(a, b) {
  if (!a || !b) return 0.5;
  let s = 0;
  // Time-of-day bucket match (morning/afternoon/evening/night)
  if (a.todBucket && b.todBucket && a.todBucket === b.todBucket) s += 0.4;
  // Weekday match
  if (a.dayOfWeek !== undefined && b.dayOfWeek !== undefined && a.dayOfWeek === b.dayOfWeek) s += 0.2;
  // Visit count similarity (frequent vs infrequent)
  if (a.visitBucket && b.visitBucket && a.visitBucket === b.visitBucket) s += 0.4;
  return s;
}

// ================================================================
//  UTILITY
// ================================================================

function weightedFieldMatch(a, b, fields) {
  let matched = 0, total = 0;
  for (const [key, weight] of fields) {
    total += weight;
    if (a[key] !== undefined && a[key] !== null && a[key] === b[key]) {
      matched += weight;
    }
  }
  return total > 0 ? matched / total : 0;
}

module.exports = { compareProfiles, CONFIDENCE_THRESHOLD };
