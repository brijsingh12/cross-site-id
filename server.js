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

// ---- Bounce redirect (PRIMARY cross-site mechanism for Safari) ----
//
//  Safari flow:
//    1. Client on shop.com has no local token
//    2. Client redirects to: identity-server.com/bounce?r=shop.com/page
//    3. During this redirect, identity-server.com IS first-party
//    4. Server reads its HttpOnly cookie (_ntrx_sid)
//       - Cookie exists → user visited another partner site before → SAME token
//       - Cookie doesn't exist → new user → generate new token
//    5. Server sets/refreshes HttpOnly cookie (400-day, NOT capped by ITP)
//    6. Server redirects back to shop.com/page?_ntrx_tok=the-token
//    7. Client reads token from URL, stores locally → done
//
app.get('/bounce', function (req, res) {
  var returnUrl = req.query.r;
  if (!returnUrl || !/^https?:\/\//.test(returnUrl)) {
    return res.status(400).send('Missing or invalid return URL');
  }

  // Read existing cookie OR create new token
  var id = req.cookies._ntrx_sid;
  var isNew = false;
  if (!id || typeof id !== 'string' || !id.startsWith('ntrx_')) {
    id = 'ntrx_' + crypto.randomUUID();
    isNew = true;
  }

  // Set first-party HttpOnly cookie on OUR domain
  // This is NOT capped by Safari ITP because:
  //   1. We are the first-party during this navigation
  //   2. It's set via Set-Cookie header, not document.cookie
  //   3. HttpOnly cookies are not subject to the 7-day JS cookie cap
  res.cookie('_ntrx_sid', id, {
    maxAge:   400 * 24 * 60 * 60 * 1000, // 400 days
    httpOnly: true,
    secure:   true,
    sameSite: 'none'  // allow cross-site redirect flow
  });

  registry.register(id, 'bounce:' + (isNew ? 'new' : 'existing'));

  var sep = returnUrl.indexOf('?') !== -1 ? '&' : '?';
  res.redirect(302, returnUrl + sep + '_ntrx_tok=' + encodeURIComponent(id));
});

// ---- Silent bounce-set (sets cookie without redirect, for background registration) ----
//  Called via <img src="/bounce-set?t=token"> from the client after generating a new UUID.
//  This ensures the server has the token in its cookie for future cross-site bounces.
app.get('/bounce-set', function (req, res) {
  var token = req.query.t;
  var existing = req.cookies._ntrx_sid;

  // If server already has a cookie, don't overwrite (first device wins)
  var id = existing && existing.startsWith('ntrx_') ? existing : token;

  if (id && id.startsWith('ntrx_')) {
    res.cookie('_ntrx_sid', id, {
      maxAge:   400 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure:   true,
      sameSite: 'none'
    });
    registry.register(id, 'bounce-set');
  }

  // Return a 1x1 transparent pixel
  var pixel = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
  res.set({ 'Content-Type': 'image/gif', 'Cache-Control': 'no-store' });
  res.send(pixel);
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
  console.log('  Cross-Site Identity Server v4 (Safari-First)');
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
