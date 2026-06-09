'use strict';

const express = require('express');
const crypto  = require('crypto');
const path    = require('path');
const fs      = require('fs');
const cors    = require('cors');
const cookieParser  = require('cookie-parser');
const compression   = require('compression');
const helmet        = require('helmet');

const app  = express();
const PORT = process.env.PORT || 3000;

// ==================================================================
//  IN-MEMORY TOKEN REGISTRY (persisted to disk)
// ==================================================================
const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH  = path.join(DATA_DIR, 'tokens.json');

const registry = {
  tokens: new Map(),  // tokenId → { sites: [], created, lastSeen }
  dirty: false,

  register(id, site) {
    let rec = this.tokens.get(id);
    if (!rec) {
      rec = { sites: [], created: Date.now(), lastSeen: Date.now() };
      this.tokens.set(id, rec);
    }
    rec.lastSeen = Date.now();
    if (!rec.sites.includes(site)) {
      rec.sites.push(site);
      if (rec.sites.length > 100) rec.sites.shift();
    }
    this.dirty = true;
    return rec;
  },

  exists(id) {
    return this.tokens.has(id);
  },

  load() {
    try {
      const raw = fs.readFileSync(DB_PATH, 'utf-8');
      const data = JSON.parse(raw);
      for (const [id, rec] of Object.entries(data.tokens || {})) {
        this.tokens.set(id, rec);
      }
      console.log('[registry] loaded ' + this.tokens.size + ' tokens');
    } catch (e) {
      if (e.code !== 'ENOENT') console.warn('[registry] load error:', e.message);
      console.log('[registry] starting empty');
    }
  },

  save() {
    if (!this.dirty) return;
    const data = { tokens: {} };
    for (const [id, rec] of this.tokens) {
      data.tokens[id] = rec;
    }
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
    this.dirty = false;
  },

  stats() {
    return { tokens: this.tokens.size };
  }
};

// ==================================================================
//  MIDDLEWARE
// ==================================================================
app.use(compression());
app.use(cookieParser());
app.use(express.json({ limit: '8kb' }));

app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  crossOriginOpenerPolicy: false,
  contentSecurityPolicy: false
}));

app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
  maxAge: 86400
}));

// ==================================================================
//  ROUTES
// ==================================================================

// ---- Client script ----
app.get('/id-generator.js', function (req, res) {
  res.set({
    'Content-Type': 'application/javascript; charset=utf-8',
    'Cache-Control': 'public, max-age=3600, stale-while-revalidate=86400'
  });
  res.sendFile(path.join(__dirname, 'public', 'id-generator.js'));
});

// ---- Iframe bridge ----
app.get('/bridge.html', function (req, res) {
  res.set({
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-cache',
    'X-Frame-Options': 'ALLOWALL'
  });
  res.sendFile(path.join(__dirname, 'public', 'bridge.html'));
});

// ---- Register token (called by client after ID is resolved) ----
app.post('/api/register', function (req, res) {
  var id   = req.body && req.body.id;
  var site = req.body && req.body.site;

  if (!id || typeof id !== 'string' || id.length < 10) {
    return res.status(400).json({ error: 'invalid token' });
  }

  var rec = registry.register(id, site || 'unknown');

  res.json({
    id: id,
    sites: rec.sites.length,
    isNew: rec.sites.length === 1 && Date.now() - rec.created < 5000
  });
});

// ---- Bounce redirect (Safari fallback when iframe bridge fails) ----
app.get('/bounce', function (req, res) {
  var returnUrl = req.query.r;
  if (!returnUrl || !/^https?:\/\//.test(returnUrl)) {
    return res.status(400).send('Missing or invalid return URL');
  }

  // Read or create token from our first-party cookie
  var id = req.cookies._ntrx_sid;
  if (!id) {
    id = 'ntrx_' + crypto.randomUUID();
  }

  // Set first-party cookie on OUR domain (we ARE first-party during bounce)
  res.cookie('_ntrx_sid', id, {
    maxAge:   400 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure:   true,
    sameSite: 'lax'
  });

  registry.register(id, 'bounce');

  var sep = returnUrl.indexOf('?') !== -1 ? '&' : '?';
  res.redirect(302, returnUrl + sep + '_ntrx_tok=' + encodeURIComponent(id));
});

// ---- Test pages ----
app.get('/test-shop.html',   function (req, res) { res.sendFile(path.join(__dirname, 'test-shop.html')); });
app.get('/test-crow.html',   function (req, res) { res.sendFile(path.join(__dirname, 'test-crow.html')); });
app.get('/test-pewpie.html', function (req, res) { res.sendFile(path.join(__dirname, 'test-pewpie.html')); });

// ---- Health ----
app.get('/health', function (req, res) {
  res.json({ ok: true, uptime: process.uptime(), ...registry.stats() });
});

// ==================================================================
//  LIFECYCLE
// ==================================================================
registry.load();

app.listen(PORT, function () {
  console.log('');
  console.log('  Cross-Site Identity Server v3 (Token-Based)');
  console.log('  --------------------------------------------');
  console.log('  Port:    ' + PORT);
  console.log('  Script:  http://localhost:' + PORT + '/id-generator.js');
  console.log('  Bridge:  http://localhost:' + PORT + '/bridge.html');
  console.log('  Health:  http://localhost:' + PORT + '/health');
  console.log('');
});

var saveInterval = setInterval(function () { registry.save(); }, 60000);

function shutdown() {
  clearInterval(saveInterval);
  registry.save();
  process.exit(0);
}
process.on('SIGINT',  shutdown);
process.on('SIGTERM', shutdown);
