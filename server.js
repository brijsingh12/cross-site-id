'use strict';

const express = require('express');
const crypto  = require('crypto');
const path    = require('path');
const cors    = require('cors');
const cookieParser  = require('cookie-parser');
const compression   = require('compression');
const helmet        = require('helmet');
const IdentityStore = require('./lib/store');

const app   = express();
const store = new IdentityStore();
const PORT  = process.env.PORT || 3000;

// ==================================================================
//  MIDDLEWARE
// ==================================================================

app.use(compression());
app.use(cookieParser());
app.use(express.json({ limit: '16kb' }));

// Security headers — relaxed enough for cross-origin script & iframe usage
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  crossOriginOpenerPolicy: false,
  contentSecurityPolicy: false   // partner sites control their own CSP
}));

// CORS — must accept ANY origin (the script runs on partner domains)
// credentials: true so we can set/read cookies via fetch where supported
app.use(cors({
  origin: true,           // reflect request origin
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
  maxAge: 86400
}));

// ==================================================================
//  ROUTES
// ==================================================================

// ---- Serve client script (the <script src="…"> target) ----
app.get('/id-generator.js', function (req, res) {
  res.set({
    'Content-Type': 'application/javascript; charset=utf-8',
    'Cache-Control': 'public, max-age=3600, stale-while-revalidate=86400'
  });
  res.sendFile(path.join(__dirname, 'public', 'id-generator.js'));
});

// ---- Iframe bridge (Storage Access API page) ----
app.get('/bridge.html', function (req, res) {
  res.set({
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-cache',
    // Allow being embedded in any partner site's iframe
    'X-Frame-Options': 'ALLOWALL'
  });
  res.sendFile(path.join(__dirname, 'public', 'bridge.html'));
});

// ---- Main identity resolution endpoint ----
app.post('/api/resolve', function (req, res) {
  try {
    var b = req.body || {};
    var core   = b.core;
    var device = b.device;
    var full   = b.full;

    if (!core || !device || !full) {
      return res.status(400).json({ error: 'Missing fingerprint hashes' });
    }

    var result = store.resolve(
      core,
      device,
      full,
      b.signals || {},
      b.localId || null,
      b.site || 'unknown'
    );

    res.json({
      id:     result.id,
      method: result.method,
      isNew:  result.isNew
    });
  } catch (e) {
    console.error('[resolve] error:', e);
    res.status(500).json({ error: 'internal' });
  }
});

// ---- Bounce redirect (Safari fallback) ----
//  Client navigates here → server sets first-party cookie → redirects back with token
app.get('/bounce', function (req, res) {
  var returnUrl = req.query.r;
  if (!returnUrl || !/^https?:\/\//.test(returnUrl)) {
    return res.status(400).send('Missing or invalid return URL');
  }

  // Read existing cookie or create new identity
  var id = req.cookies._ntrx_sid;
  if (!id) {
    id = 'ntrx_' + crypto.randomUUID();
  }

  // Set first-party cookie on OUR domain (we ARE first-party during the bounce)
  res.cookie('_ntrx_sid', id, {
    maxAge:   400 * 24 * 60 * 60 * 1000, // 400 days
    httpOnly: true,
    secure:   true,
    sameSite: 'lax'
  });

  // Redirect back with the ID as an encrypted-ish token
  var sep = returnUrl.indexOf('?') !== -1 ? '&' : '?';
  res.redirect(302, returnUrl + sep + '_ntrx_tok=' + encodeURIComponent(id));
});

// ---- Serve test pages (for local development) ----
app.get('/test-shop.html',   function (req, res) { res.sendFile(path.join(__dirname, 'test-shop.html')); });
app.get('/test-crow.html',   function (req, res) { res.sendFile(path.join(__dirname, 'test-crow.html')); });
app.get('/test-pewpie.html', function (req, res) { res.sendFile(path.join(__dirname, 'test-pewpie.html')); });

// ---- Health / stats ----
app.get('/health', function (req, res) {
  res.json({ ok: true, uptime: process.uptime(), ...store.stats() });
});

// ==================================================================
//  LIFECYCLE
// ==================================================================

store.load().then(function () {
  app.listen(PORT, function () {
    console.log('');
    console.log('  Cross-Site Identity Server running');
    console.log('  -----------------------------------');
    console.log('  Port:    ' + PORT);
    console.log('  Script:  http://localhost:' + PORT + '/id-generator.js');
    console.log('  Bridge:  http://localhost:' + PORT + '/bridge.html');
    console.log('  Health:  http://localhost:' + PORT + '/health');
    console.log('');
  });
});

// Persist identity graph periodically and on shutdown
var saveInterval = setInterval(function () { store.save(); }, 60000);

function gracefulShutdown() {
  clearInterval(saveInterval);
  store.save();
  process.exit(0);
}
process.on('SIGINT',  gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);
