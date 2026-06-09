'use strict';

const express = require('express');
const crypto  = require('crypto');
const path    = require('path');
const cors    = require('cors');
const cookieParser  = require('cookie-parser');
const compression   = require('compression');
const helmet        = require('helmet');
const ProfileStore  = require('./lib/profile-store');

const app   = express();
const store = new ProfileStore();
const PORT  = process.env.PORT || 3000;

// ==================================================================
//  MIDDLEWARE
// ==================================================================
app.use(compression());
app.use(cookieParser());
app.use(express.json({ limit: '32kb' }));

// Trust proxy for accurate IP (Railway, Heroku, etc.)
app.set('trust proxy', true);

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
//  IP INTELLIGENCE — extract from request
// ==================================================================
function extractIPIntel(req) {
  const ip = req.ip || req.connection.remoteAddress || '';
  const clean = ip.replace(/^::ffff:/, '');
  const parts = clean.split('.');
  const subnet = parts.length === 4 ? parts.slice(0, 3).join('.') + '.0/24' : clean;

  return {
    ip: clean,
    subnet: subnet,
    // ASN would come from a GeoIP database in production (e.g., MaxMind)
    asn: null
  };
}

// ==================================================================
//  SERVER-SIDE ANALYSIS — header fingerprint
// ==================================================================
function extractHeaderIntel(req) {
  return {
    accept: req.headers['accept'] || '',
    acceptLanguage: req.headers['accept-language'] || '',
    acceptEncoding: req.headers['accept-encoding'] || '',
    // Connection and upgrade-insecure-requests reveal browser identity
    connection: req.headers['connection'] || '',
    uir: req.headers['upgrade-insecure-requests'] || ''
  };
}

// ==================================================================
//  ROUTES
// ==================================================================

// ---- Client script ----
app.get('/id-generator.js', function (req, res) {
  res.set({
    'Content-Type': 'application/javascript; charset=utf-8',
    'Cache-Control': 'public, max-age=300, stale-while-revalidate=3600'
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

// ---- Register + Profile Update ----
//  Called by the client to register a known token AND update its profile
//  with all collected signals (fingerprint, device, behavior, locale).
app.post('/api/register', function (req, res) {
  const b = req.body || {};
  const id = b.id;

  if (!id || typeof id !== 'string' || !id.startsWith('ntrx_') || id.length < 10) {
    return res.status(400).json({ error: 'invalid token' });
  }

  // Build the full signal profile from client + server signals
  const signals = {
    site: b.site || 'unknown',
    ip: extractIPIntel(req),
    fingerprint: b.fingerprint || {},
    device: b.device || {},
    behavior: b.behavior || {},
    headers: extractHeaderIntel(req),
    locale: b.locale || {}
  };

  const profile = store.upsert(id, signals);

  res.json({
    id: id,
    sites: profile.sites.length,
    visitCount: profile.visitCount
  });
});

// ---- Identity Recovery ----
//  When the client has NO token (all local storage cleared), it sends
//  its signals here. The server uses ML-weighted matching to find the
//  most likely previous identity. Only matches if confidence >= 82%
//  AND the match is unambiguous (prevents collision on identical hardware).
app.post('/api/recover', function (req, res) {
  const b = req.body || {};

  const probe = {
    ip: extractIPIntel(req),
    fingerprint: b.fingerprint || {},
    device: b.device || {},
    behavior: b.behavior || {},
    headers: extractHeaderIntel(req),
    locale: b.locale || {},
    site: b.site || 'unknown'
  };

  const match = store.findMatch(probe);

  if (match) {
    // Update the matched profile with new signals
    store.upsert(match.tokenId, probe);

    res.json({
      id: match.tokenId,
      recovered: true,
      confidence: match.score,
      ambiguityGap: match.ambiguityGap,
      method: 'ml-match'
    });
  } else {
    // No confident match — client should generate a new UUID
    res.json({
      id: null,
      recovered: false,
      method: 'no-match'
    });
  }
});

// ---- Bounce redirect (PRIMARY cross-site mechanism for Safari) ----
app.get('/bounce', function (req, res) {
  const returnUrl = req.query.r;
  if (!returnUrl || !/^https?:\/\//.test(returnUrl)) {
    return res.status(400).send('Missing or invalid return URL');
  }

  let id = req.cookies._ntrx_sid;
  const isNew = !id || !id.startsWith('ntrx_');
  if (isNew) {
    id = 'ntrx_' + crypto.randomUUID();
  }

  // HttpOnly + Secure + SameSite=None → survives ITP, works in redirect flow
  res.cookie('_ntrx_sid', id, {
    maxAge:   400 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure:   true,
    sameSite: 'none'
  });

  store.upsert(id, {
    site: 'bounce',
    ip: extractIPIntel(req),
    headers: extractHeaderIntel(req)
  });

  const sep = returnUrl.indexOf('?') !== -1 ? '&' : '?';
  res.redirect(302, returnUrl + sep + '_ntrx_tok=' + encodeURIComponent(id));
});

// ---- Silent bounce-set (pixel-based cookie setter) ----
app.get('/bounce-set', function (req, res) {
  const token = req.query.t;
  const existing = req.cookies._ntrx_sid;

  const id = (existing && existing.startsWith('ntrx_')) ? existing : token;

  if (id && id.startsWith('ntrx_')) {
    res.cookie('_ntrx_sid', id, {
      maxAge:   400 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure:   true,
      sameSite: 'none'
    });
    store.upsert(id, { site: 'bounce-set', ip: extractIPIntel(req) });
  }

  const pixel = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
  res.set({ 'Content-Type': 'image/gif', 'Cache-Control': 'no-store' });
  res.send(pixel);
});

// ---- Test pages ----
app.get('/test-shop.html',   function (req, res) { res.sendFile(path.join(__dirname, 'test-shop.html')); });
app.get('/test-crow.html',   function (req, res) { res.sendFile(path.join(__dirname, 'test-crow.html')); });
app.get('/test-pewpie.html', function (req, res) { res.sendFile(path.join(__dirname, 'test-pewpie.html')); });

// ---- Health / stats ----
app.get('/health', function (req, res) {
  res.json({
    ok: true,
    version: 4,
    uptime: process.uptime(),
    ...store.stats()
  });
});

// ==================================================================
//  LIFECYCLE
// ==================================================================
store.load();

app.listen(PORT, function () {
  console.log('');
  console.log('  Cross-Site Identity Server v4 (Full Intelligence)');
  console.log('  --------------------------------------------------');
  console.log('  Port:    ' + PORT);
  console.log('  Script:  http://localhost:' + PORT + '/id-generator.js');
  console.log('  Health:  http://localhost:' + PORT + '/health');
  console.log('');
});

setInterval(function () { store.save(); }, 60000);
process.on('SIGINT',  function () { store.save(); process.exit(0); });
process.on('SIGTERM', function () { store.save(); process.exit(0); });
