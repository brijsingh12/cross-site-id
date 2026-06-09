'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', 'data', 'identities.json');

/**
 * IdentityStore — server-side identity graph with tiered fingerprint matching.
 *
 * Index structure (all in-memory, persisted to disk):
 *   coreIndex:   coreHash   → userId        (O(1) primary lookup)
 *   fullIndex:   fullHash   → userId        (O(1) secondary lookup)
 *   deviceIndex: deviceHash → Set<userId>   (bucket for fuzzy matching)
 *   users:       userId     → UserRecord
 *
 * Resolution order:
 *   1. Exact coreHash match
 *   2. Exact fullHash match
 *   3. Valid localId confirmation
 *   4. Device-bucket fuzzy match (weighted signal similarity)
 *   5. New user creation
 */
class IdentityStore {
  constructor() {
    this.coreIndex   = new Map(); // coreHash → userId
    this.fullIndex   = new Map(); // fullHash → userId
    this.deviceIndex = new Map(); // deviceHash → Set<userId>
    this.users       = new Map(); // userId → UserRecord
    this._dirty = false;
  }

  // ----------------------------------------------------------------
  //  PUBLIC: resolve an identity
  // ----------------------------------------------------------------
  resolve(coreHash, deviceHash, fullHash, signals, localId, site) {
    // 1. Exact core match (fastest, most reliable)
    let uid = this.coreIndex.get(coreHash);
    if (uid && this.users.has(uid)) {
      this._touch(uid, site, { core: coreHash, device: deviceHash, full: fullHash }, signals);
      return { id: uid, method: 'core', isNew: false };
    }

    // 2. Exact full match (core may have shifted due to browser update)
    uid = this.fullIndex.get(fullHash);
    if (uid && this.users.has(uid)) {
      this.coreIndex.set(coreHash, uid); // update core index
      this._touch(uid, site, { core: coreHash, device: deviceHash, full: fullHash }, signals);
      return { id: uid, method: 'full', isNew: false };
    }

    // 3. Known localId from the client — trust it if it exists in our graph
    if (localId && this.users.has(localId)) {
      this.coreIndex.set(coreHash, localId);
      this.fullIndex.set(fullHash, localId);
      this._addDevice(deviceHash, localId);
      this._touch(localId, site, { core: coreHash, device: deviceHash, full: fullHash }, signals);
      return { id: localId, method: 'local', isNew: false };
    }

    // 4. Fuzzy match inside device bucket
    const candidates = this.deviceIndex.get(deviceHash);
    if (candidates && candidates.size > 0) {
      const best = this._bestFuzzyMatch(candidates, signals);
      if (best) {
        this.coreIndex.set(coreHash, best);
        this.fullIndex.set(fullHash, best);
        this._touch(best, site, { core: coreHash, device: deviceHash, full: fullHash }, signals);
        return { id: best, method: 'fuzzy', isNew: false };
      }
    }

    // 5. New user
    uid = 'ntrx_' + crypto.randomUUID();
    this.users.set(uid, {
      fingerprints: [{ core: coreHash, device: deviceHash, full: fullHash }],
      signals,
      sites: [site],
      created: Date.now(),
      lastSeen: Date.now()
    });
    this.coreIndex.set(coreHash, uid);
    this.fullIndex.set(fullHash, uid);
    this._addDevice(deviceHash, uid);
    this._dirty = true;

    return { id: uid, method: 'new', isNew: true };
  }

  // ----------------------------------------------------------------
  //  FUZZY MATCHING — weighted signal comparison
  // ----------------------------------------------------------------
  _bestFuzzyMatch(candidateSet, signals) {
    if (!signals) return null;

    const WEIGHTS = [
      ['webglRenderer', 5],  // GPU string — hardware-locked, never changes
      ['webglVendor',   5],
      ['math',          4],  // JS engine constants — stable across sessions
      ['platform',      3],
      ['hc',            3],  // hardware concurrency — CPU core count
      ['mtp',           3],  // max touch points — device type
      ['sw',            2],  // screen dimensions
      ['sh',            2],
      ['dpr',           2],  // device pixel ratio
      ['tz',            2],  // timezone
      ['dm',            1],  // device memory
      ['cd',            1],  // color depth
      ['langCount',     1]
    ];

    const THRESHOLD = 0.70;
    let bestId = null;
    let bestScore = 0;

    for (const uid of candidateSet) {
      const user = this.users.get(uid);
      if (!user || !user.signals) continue;

      let matched = 0, total = 0;
      for (const [key, w] of WEIGHTS) {
        total += w;
        if (signals[key] !== undefined && signals[key] === user.signals[key]) {
          matched += w;
        }
      }

      const score = total > 0 ? matched / total : 0;
      if (score > bestScore && score >= THRESHOLD) {
        bestScore = score;
        bestId = uid;
      }
    }

    return bestId;
  }

  // ----------------------------------------------------------------
  //  INTERNAL HELPERS
  // ----------------------------------------------------------------
  _touch(uid, site, hashes, signals) {
    let rec = this.users.get(uid);
    if (!rec) {
      rec = { fingerprints: [], signals: {}, sites: [], created: Date.now(), lastSeen: Date.now() };
      this.users.set(uid, rec);
    }

    rec.lastSeen = Date.now();
    if (signals) rec.signals = signals;

    // Track sites (cap at 100)
    if (!rec.sites.includes(site)) {
      rec.sites.push(site);
      if (rec.sites.length > 100) rec.sites.shift();
    }

    // Track fingerprint variants (cap at 10)
    const dominated = rec.fingerprints.some(
      fp => fp.core === hashes.core && fp.full === hashes.full
    );
    if (!dominated) {
      rec.fingerprints.push(hashes);
      if (rec.fingerprints.length > 10) rec.fingerprints.shift();
    }

    // Keep indexes consistent
    this.coreIndex.set(hashes.core, uid);
    this.fullIndex.set(hashes.full, uid);
    this._addDevice(hashes.device, uid);
    this._dirty = true;
  }

  _addDevice(deviceHash, uid) {
    let set = this.deviceIndex.get(deviceHash);
    if (!set) {
      set = new Set();
      this.deviceIndex.set(deviceHash, set);
    }
    set.add(uid);
  }

  // ----------------------------------------------------------------
  //  PERSISTENCE (JSON file)
  // ----------------------------------------------------------------
  async load() {
    try {
      const raw = fs.readFileSync(DB_PATH, 'utf-8');
      const data = JSON.parse(raw);

      for (const [uid, rec] of Object.entries(data.users || {})) {
        // Restore sites as array
        rec.sites = rec.sites || [];
        this.users.set(uid, rec);

        for (const fp of rec.fingerprints || []) {
          this.coreIndex.set(fp.core, uid);
          this.fullIndex.set(fp.full, uid);
          this._addDevice(fp.device, uid);
        }
      }

      console.log(`[store] loaded ${this.users.size} identities`);
    } catch (e) {
      if (e.code !== 'ENOENT') console.warn('[store] load error:', e.message);
      console.log('[store] starting with empty identity graph');
    }
  }

  save() {
    if (!this._dirty) return;

    const data = { users: {} };
    for (const [uid, rec] of this.users) {
      data.users[uid] = {
        fingerprints: rec.fingerprints,
        signals: rec.signals,
        sites: rec.sites,
        created: rec.created,
        lastSeen: rec.lastSeen
      };
    }

    const dir = path.dirname(DB_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
    this._dirty = false;
    console.log(`[store] persisted ${this.users.size} identities`);
  }

  // ----------------------------------------------------------------
  //  STATS
  // ----------------------------------------------------------------
  stats() {
    return {
      users: this.users.size,
      coreIndexEntries: this.coreIndex.size,
      fullIndexEntries: this.fullIndex.size,
      deviceBuckets: this.deviceIndex.size
    };
  }
}

module.exports = IdentityStore;
