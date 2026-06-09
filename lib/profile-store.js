'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { compareProfiles, CONFIDENCE_THRESHOLD } = require('./matcher');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DB_PATH  = path.join(DATA_DIR, 'profiles.json');

/**
 * ProfileStore — identity profiles with multi-signal matching.
 *
 * Each token has an associated profile containing:
 *   - IP intelligence (ip, subnet, asn)
 *   - Browser fingerprint (canvas, webgl, audio, math, fonts hashes)
 *   - Device intelligence (gpu, screen, hardware, platform)
 *   - Behavioral signals (mouse speed, scroll speed, interaction timing)
 *   - Header fingerprint (accept, accept-language, accept-encoding)
 *   - Locale/timezone signals
 *   - Historical patterns (time-of-day, visit frequency)
 *
 * When a request arrives WITHOUT a token, the store searches all profiles
 * for a high-confidence match. Only returns a match if confidence >= 82%
 * AND the match is unambiguous (no other profile scores within 10%).
 */
class ProfileStore {
  constructor() {
    this.profiles = new Map(); // tokenId → profile
    this._dirty = false;
  }

  /**
   * Register/update a profile for a known token.
   */
  upsert(tokenId, signals) {
    let profile = this.profiles.get(tokenId);
    if (!profile) {
      profile = {
        created: Date.now(),
        lastSeen: Date.now(),
        visitCount: 0,
        sites: [],
        // Signal categories (updated over time)
        ip: {},
        fingerprint: {},
        device: {},
        behavior: {},
        headers: {},
        locale: {},
        history: {}
      };
      this.profiles.set(tokenId, profile);
    }

    profile.lastSeen = Date.now();
    profile.visitCount++;

    // Update signals (merge, don't overwrite with empty)
    if (signals.ip) profile.ip = { ...profile.ip, ...signals.ip };
    if (signals.fingerprint) profile.fingerprint = { ...profile.fingerprint, ...signals.fingerprint };
    if (signals.device) profile.device = { ...profile.device, ...signals.device };
    if (signals.behavior && signals.behavior.mouseSpeed) {
      // Exponential moving average for behavioral signals
      if (profile.behavior.mouseSpeed) {
        profile.behavior.mouseSpeed = profile.behavior.mouseSpeed * 0.7 + signals.behavior.mouseSpeed * 0.3;
        profile.behavior.scrollSpeed = (profile.behavior.scrollSpeed || 0) * 0.7 + (signals.behavior.scrollSpeed || 0) * 0.3;
      } else {
        profile.behavior = { ...profile.behavior, ...signals.behavior };
      }
      profile.behavior.interactionBucket = signals.behavior.interactionBucket;
    }
    if (signals.headers) profile.headers = { ...profile.headers, ...signals.headers };
    if (signals.locale) profile.locale = { ...profile.locale, ...signals.locale };

    // Update history patterns
    const hour = new Date().getHours();
    profile.history.todBucket = hour < 6 ? 'night' : hour < 12 ? 'morning' : hour < 18 ? 'afternoon' : 'evening';
    profile.history.dayOfWeek = new Date().getDay();
    profile.history.visitBucket = profile.visitCount < 3 ? 'new' : profile.visitCount < 10 ? 'regular' : 'frequent';

    // Track sites
    const site = signals.site;
    if (site && !profile.sites.includes(site)) {
      profile.sites.push(site);
      if (profile.sites.length > 100) profile.sites.shift();
    }

    this._dirty = true;
    return profile;
  }

  /**
   * Find the best matching token for a set of signals.
   * Returns { tokenId, score, breakdown } or null if no confident match.
   *
   * ANTI-COLLISION: requires the best match to be significantly better
   * than the second-best match (ambiguity check).
   */
  findMatch(signals) {
    if (this.profiles.size === 0) return null;

    const probe = {
      ip: signals.ip || {},
      fingerprint: signals.fingerprint || {},
      device: signals.device || {},
      behavior: signals.behavior || {},
      headers: signals.headers || {},
      locale: signals.locale || {},
      history: {
        todBucket: (() => { var h = new Date().getHours(); return h < 6 ? 'night' : h < 12 ? 'morning' : h < 18 ? 'afternoon' : 'evening'; })(),
        dayOfWeek: new Date().getDay()
      }
    };

    let bestId = null;
    let bestScore = 0;
    let bestBreakdown = null;
    let secondBestScore = 0;

    for (const [tokenId, profile] of this.profiles) {
      const result = compareProfiles(profile, probe);

      if (result.score > bestScore) {
        secondBestScore = bestScore;
        bestScore = result.score;
        bestId = tokenId;
        bestBreakdown = result.breakdown;
      } else if (result.score > secondBestScore) {
        secondBestScore = result.score;
      }
    }

    // ANTI-COLLISION CHECK:
    // 1. Must exceed confidence threshold
    // 2. Must be significantly better than second-best (ambiguity gap >= 0.10)
    //    This prevents matching when multiple profiles look similar (e.g., identical hardware)
    const ambiguityGap = bestScore - secondBestScore;
    const isUnambiguous = ambiguityGap >= 0.10 || this.profiles.size === 1;

    if (bestScore >= CONFIDENCE_THRESHOLD && isUnambiguous) {
      return {
        tokenId: bestId,
        score: bestScore,
        ambiguityGap: Math.round(ambiguityGap * 1000) / 1000,
        breakdown: bestBreakdown
      };
    }

    return null;
  }

  exists(tokenId) {
    return this.profiles.has(tokenId);
  }

  stats() {
    return { profiles: this.profiles.size };
  }

  // ---- Persistence ----

  load() {
    try {
      const raw = fs.readFileSync(DB_PATH, 'utf-8');
      const data = JSON.parse(raw);
      for (const [id, p] of Object.entries(data.profiles || {})) {
        this.profiles.set(id, p);
      }
      console.log('[profiles] loaded ' + this.profiles.size + ' profiles');
    } catch (e) {
      if (e.code !== 'ENOENT') console.warn('[profiles] load error:', e.message);
      console.log('[profiles] starting empty');
    }
  }

  save() {
    if (!this._dirty) return;
    const data = { profiles: {} };
    for (const [id, p] of this.profiles) {
      data.profiles[id] = p;
    }
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(DB_PATH, JSON.stringify(data));
    this._dirty = false;
  }
}

module.exports = ProfileStore;
