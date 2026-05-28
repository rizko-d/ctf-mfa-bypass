/**
 * CTF Lab: Admin Feedback System (Intentionally Vulnerable)
 * Scenario: Cookies Reuse & MFA Bypass
 * Port: 3075
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');

const app = express();

const LOG_DIR = '/opt/admin/logs';
const ACCESS_LOG = path.join(LOG_DIR, 'access.log');
const ERROR_LOG = path.join(LOG_DIR, 'error.log');

// Hardcoded "stolen" admin session that the attacker will replay
const VALID_ADMIN_SESSION = 'adm_sess_4dm1n_s3cr3t_t0k3n_2024';

// Ensure log directory exists
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

// ─── Helper: write to error.log ───────────────────────────────────────────────

function writeError(level, message) {
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 19);
  fs.appendFileSync(ERROR_LOG, `[${ts}] [${level}] ${message}\n`);
}

// ─── Middleware ────────────────────────────────────────────────────────────────

// PHASE 1: Expose X-Powered-By → Node.js (CTF flag: SCENARIO75{Node.js})
app.use((req, res, next) => {
  res.removeHeader('X-Powered-By');
  res.setHeader('X-Powered-By', 'Node.js');
  next();
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Nginx-style access logger
app.use((req, res, next) => {
  res.on('finish', () => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '-';
    const ua = req.headers['user-agent'] || '-';
    const xff = req.headers['x-forwarded-for'] || '-';
    const ts = new Date().toISOString().replace('T', ' ').slice(0, 19);
    const line =
      `${ip} - - [${ts}] "${req.method} ${req.url} HTTP/1.1" ` +
      `${res.statusCode} - "-" "${ua}" X-Forwarded-For: ${xff}\n`;
    fs.appendFileSync(ACCESS_LOG, line);
  });
  next();
});

// ─── WAF Middleware ────────────────────────────────────────────────────────────
// PHASE 2: Blocks <script>, blocks document.cookie; bypassed by <svg onload=...>
//          and window['docu'+'ment']['coo'+'kie']

function waf(req, res, next) {
  const body = JSON.stringify(req.body || '');

  // Block <script> → returns 403 (CTF flag: SCENARIO75{403})
  if (/<script/i.test(body)) {
    writeError('WARN', `WAF BLOCK from ${req.ip}: detected payload "<script>" at ${req.url}`);
    return res.status(403).send('WAF: Forbidden. Malicious payload detected.');
  }

  // Block direct document.cookie access (force bracket-notation obfuscation)
  if (/document\.cookie/i.test(body)) {
    writeError('WARN', `WAF BLOCK from ${req.ip}: detected payload "document.cookie" at ${req.url}`);
    return res.status(403).send('WAF: Forbidden. Cookie access denied.');
  }

  // <svg> payloads and window['docu'+'ment']['coo'+'kie'] pass through ✓
  next();
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// robots.txt — disallows /api/verify-mfa (CTF flags: SCENARIO75{/api/verify-mfa}, SCENARIO75{/dashboard})
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send(
    'User-agent: *\n' +
    'Disallow: /api/verify-mfa\n' +
    'Disallow: /dashboard\n'
  );
});

// Home / Login page
// Sets pre_mfa_session cookie with HttpOnly=false (CTF flags: SCENARIO75{pre_mfa_session}, SCENARIO75{pending_mfa_verification}, SCENARIO75{False})
// Contains ASCII art hinting at robots.txt (CTF flag: SCENARIO75{robots.txt})
app.get('/', (req, res) => {
  res.cookie('pre_mfa_session', 'pending_mfa_verification', {
    httpOnly: false,   // ← intentionally false (SCENARIO75{False})
    path: '/',
    sameSite: 'Lax'
  });

  res.send(`<!DOCTYPE html>
<html lang="en">
<!--
 ██████╗  ██████╗ ██████╗  ██████╗ ████████╗███████╗    ████████╗██╗  ██╗████████╗
 ██╔══██╗██╔═══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝    ╚══██╔══╝╚██╗██╔╝╚══██╔══╝
 ██████╔╝██║   ██║██████╔╝██║   ██║   ██║   ███████╗       ██║    ╚███╔╝    ██║
 ██╔══██╗██║   ██║██╔══██╗██║   ██║   ██║   ╚════██║       ██║    ██╔██╗    ██║
 ██║  ██║╚██████╔╝██████╔╝╚██████╔╝   ██║   ███████║       ██║   ██╔╝ ██╗   ██║
 ╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝   ╚═╝   ╚══════╝       ╚═╝   ╚═╝  ╚═╝   ╚═╝

 [!] HINT: Curious about hidden paths? Check /robots.txt
 SCENARIO75{robots.txt}
-->
<head>
  <meta charset="UTF-8">
  <title>Admin Feedback System</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9;
           display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px;
            padding: 40px; width: 360px; box-shadow: 0 8px 24px rgba(0,0,0,.4); }
    h2 { text-align: center; color: #58a6ff; margin-bottom: 24px; font-size: 22px; }
    label { display: block; font-size: 13px; color: #8b949e; margin-bottom: 4px; }
    input { width: 100%; padding: 10px 14px; background: #0d1117; border: 1px solid #30363d;
            border-radius: 6px; color: #c9d1d9; font-size: 14px; margin-bottom: 14px; outline: none; }
    input:focus { border-color: #58a6ff; }
    button { width: 100%; padding: 11px; background: #238636; border: none; border-radius: 6px;
             color: #fff; font-size: 15px; cursor: pointer; transition: background .2s; }
    button:hover { background: #2ea043; }
    .note { font-size: 11px; color: #6e7681; text-align: center; margin-top: 14px; }
  </style>
</head>
<body>
  <div class="card">
    <h2>🔐 Admin Feedback System</h2>
    <form method="POST" action="/api/login">
      <label>Username</label>
      <input type="text" name="username" placeholder="admin" autocomplete="off">
      <label>Password</label>
      <input type="password" name="password" placeholder="••••••••">
      <button type="submit">Login</button>
    </form>
    <p class="note">MFA is enforced for all admin sessions.</p>
  </div>
</body>
</html>`);
});

// Login POST
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === 'admin') {
    res.cookie('pre_mfa_session', 'pending_mfa_verification', {
      httpOnly: false, path: '/', sameSite: 'Lax'
    });
    return res.redirect('/feedback');
  }
  return res.status(401).send('Invalid credentials.');
});

// Feedback form page
app.get('/feedback', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Submit Feedback</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9;
           display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px;
            padding: 40px; width: 500px; }
    h2 { color: #58a6ff; margin-bottom: 20px; }
    textarea { width: 100%; height: 130px; padding: 12px; background: #0d1117;
               border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9;
               font-size: 14px; resize: vertical; margin-bottom: 14px; outline: none; }
    button { padding: 11px 24px; background: #238636; border: none; border-radius: 6px;
             color: #fff; font-size: 14px; cursor: pointer; }
    .hint { font-size: 12px; color: #6e7681; margin-top: 12px; }
  </style>
</head>
<body>
  <div class="card">
    <h2>📝 Submit Admin Feedback</h2>
    <form method="POST" action="/api/feedback">
      <textarea name="feedback" placeholder="Enter your message here..."></textarea>
      <button type="submit">Submit</button>
    </form>
    <p class="hint">Feedback is reviewed by the admin team. MFA required to access the dashboard.</p>
  </div>
</body>
</html>`);
});

// Feedback submission endpoint — POST only, WAF-protected
// CTF flag: SCENARIO75{POST} (method), SCENARIO75{fetch} (exfiltration allowed)
app.post('/api/feedback', waf, (req, res) => {
  const feedback = req.body.feedback || '';
  // Store payload in a readable cookie so it gets reflected on /dashboard
  res.cookie('last_feedback', Buffer.from(feedback).toString('base64'), {
    httpOnly: false,
    path: '/'
  });
  res.send(`<!DOCTYPE html>
<html>
<head><title>Feedback Submitted</title>
<style>body{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',sans-serif;
display:flex;justify-content:center;align-items:center;height:100vh;}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:40px;text-align:center;}
h2{color:#3fb950;}a{color:#58a6ff;}</style></head>
<body>
<div class="card">
  <h2>✅ Feedback Submitted</h2>
  <p>An admin will review your message soon.</p>
  <p style="margin-top:16px;"><a href="/api/verify-mfa">Complete MFA Verification →</a></p>
</div>
</body>
</html>`);
});

// MFA verification endpoint (disallowed in robots.txt → CTF flag: SCENARIO75{/api/verify-mfa})
app.get('/api/verify-mfa', (req, res) => {
  const session = req.cookies.session || '';
  // PHASE 3: If valid admin session already present → bypass MFA entirely
  if (session.startsWith('adm_sess')) {
    writeError('CRITICAL',
      `Authentication bypass anomaly detected from ${req.ip} ` +
      `- session cookie replayed without MFA`);
    return res.redirect('/dashboard');
  }
  res.send(`<!DOCTYPE html>
<html>
<head><title>MFA Verification</title>
<style>*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;
display:flex;justify-content:center;align-items:center;height:100vh;}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:40px;width:360px;}
h2{color:#58a6ff;margin-bottom:20px;text-align:center;}
input{width:100%;padding:10px 14px;background:#0d1117;border:1px solid #30363d;
border-radius:6px;color:#c9d1d9;font-size:16px;margin-bottom:14px;letter-spacing:4px;text-align:center;}
button{width:100%;padding:11px;background:#238636;border:none;border-radius:6px;
color:#fff;font-size:15px;cursor:pointer;}</style></head>
<body>
<div class="card">
  <h2>🔑 MFA Verification</h2>
  <form method="POST" action="/api/verify-mfa">
    <input type="text" name="otp" placeholder="000000" maxlength="6">
    <button type="submit">Verify OTP</button>
  </form>
</div>
</body>
</html>`);
});

app.post('/api/verify-mfa', (req, res) => {
  const otp = (req.body.otp || '').trim();
  if (otp === '123456') {
    res.cookie('session', VALID_ADMIN_SESSION, { httpOnly: false, path: '/' });
    return res.redirect('/dashboard');
  }
  return res.status(401).send('Invalid OTP. Access denied.');
});

// Dashboard — protected by adm_sess prefix check
// PHASE 3 flags: SCENARIO75{adm_sess}, SCENARIO75{xss-payload}, SCENARIO75{/dashboard}
//                SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d}
app.get('/dashboard', (req, res) => {
  const session = req.cookies.session || '';

  if (!session.startsWith('adm_sess')) {
    return res.status(403).redirect('/');
  }

  // CRITICAL log for cookie reuse detection
  writeError('CRITICAL',
    `Cookie reuse detected - session ${session.slice(0, 20)}... ` +
    `accessed /dashboard from ${req.ip}`);

  // Decode XSS payload from cookie (raw, unescaped → intentionally vulnerable)
  let xssPayload = '';
  if (req.cookies.last_feedback) {
    try {
      xssPayload = Buffer.from(req.cookies.last_feedback, 'base64').toString('utf8');
    } catch (_) { xssPayload = ''; }
  }

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Admin Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; }
    .topbar { background: #161b22; border-bottom: 1px solid #30363d;
              padding: 14px 32px; display: flex; justify-content: space-between; align-items: center; }
    .topbar h1 { color: #58a6ff; font-size: 20px; }
    .topbar span { color: #3fb950; font-size: 13px; }
    .main { max-width: 900px; margin: 32px auto; padding: 0 20px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 10px;
            padding: 24px; margin-bottom: 20px; }
    .card h3 { color: #8b949e; font-size: 12px; text-transform: uppercase;
               letter-spacing: 1px; margin-bottom: 14px; }
    .xss-payload { background: #0d1117; border: 1px dashed #30363d;
                   border-radius: 6px; padding: 16px; min-height: 60px;
                   font-size: 14px; word-break: break-all; }
    .flag-box { background: #0d1117; border: 2px solid #f85149;
                border-radius: 8px; padding: 20px; font-family: monospace;
                color: #f85149; font-size: 18px; letter-spacing: 1px; text-align: center; }
    .badge { display: inline-block; padding: 3px 10px; border-radius: 20px;
             font-size: 12px; background: #238636; color: #fff; margin-right: 6px; }
  </style>
</head>
<body>
  <div class="topbar">
    <h1>🛡️ Admin Dashboard</h1>
    <span>● Session Active: ${session.slice(0, 18)}...</span>
  </div>
  <div class="main">

    <div class="card">
      <h3>Latest Feedback Submission</h3>
      <!-- Intentionally reflected without sanitisation — XSS landing zone -->
      <div class="xss-payload">${xssPayload}</div>
    </div>

    <div class="card">
      <h3>System Status</h3>
      <p><span class="badge">MFA</span> Enforced on all external routes</p>
      <p style="margin-top:10px;font-size:13px;color:#6e7681;">
        Internal session validation bypasses re-authentication when a valid token is present.
      </p>
    </div>

    <div class="card">
      <h3>🏴 Confidential — Capture The Flag</h3>
      <div class="flag-box">SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d}</div>
    </div>

  </div>
</body>
</html>`);
});

// 404
app.use((req, res) => res.status(404).send('404 Not Found'));

app.listen(3075, '0.0.0.0', () => {
  console.log('[*] Admin Feedback System listening on :3075');
  console.log('[*] Logs → ' + LOG_DIR);
});
