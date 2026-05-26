// api/proxy.js  –  Vercel Serverless Function
// Token wird als Umgebungsvariable SCHULKI_TOKEN gespeichert

const { CookieJar } = require('tough-cookie');
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

// Modul-Level Cache – bleibt innerhalb derselben Function-Instanz erhalten
let csrfToken  = null;
let cookieHdr  = null;

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Accept, Content-Type',
};

async function fetchCsrf() {
  try {
    const res = await fetch('https://schulki.de/login', {
      headers: { 'User-Agent': 'Mozilla/5.0', 'Referer': 'https://schulki.de/' },
      redirect: 'manual',
    });

    const setCookies = res.headers.raw()['set-cookie'] ?? [];
    let xsrfRaw = '', sessionRaw = '';

    for (const c of setCookies) {
      const xm = c.match(/XSRF-TOKEN=([^;]+)/);
      const sm = c.match(/laravel_session=([^;]+)/);
      if (xm) xsrfRaw    = xm[1];
      if (sm) sessionRaw = sm[1];
    }

    // Falls redirect → nochmals versuchen
    if (!xsrfRaw && res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location') ?? 'https://schulki.de/';
      const res2 = await fetch(loc, {
        headers: { 'User-Agent': 'Mozilla/5.0' },
        redirect: 'manual',
      });
      for (const c of (res2.headers.raw()['set-cookie'] ?? [])) {
        const xm = c.match(/XSRF-TOKEN=([^;]+)/);
        const sm = c.match(/laravel_session=([^;]+)/);
        if (xm) xsrfRaw    = xm[1];
        if (sm) sessionRaw = sm[1];
      }
    }

    csrfToken = decodeURIComponent(xsrfRaw);
    cookieHdr = [
      xsrfRaw    ? `XSRF-TOKEN=${xsrfRaw}`        : '',
      sessionRaw ? `laravel_session=${sessionRaw}` : '',
    ].filter(Boolean).join('; ');

    console.log('CSRF geholt:', csrfToken.slice(0, 20) + '...');
  } catch (e) {
    console.error('CSRF Fehler:', e.message);
  }
}

async function doPost(target, human) {
  const token = process.env.SCHULKI_TOKEN ?? '';
  const form  = new URLSearchParams({ human, _token: csrfToken ?? '' });

  return fetch(target, {
    method: 'POST',
    headers: {
      'Content-Type':  'application/x-www-form-urlencoded',
      'Accept':        'application/json',
      'Authorization': `Bearer ${token}`,
      'X-CSRF-TOKEN':  csrfToken ?? '',
      'Cookie':        cookieHdr  ?? '',
      'User-Agent':    'Mozilla/5.0',
      'Referer':       'https://schulki.de/',
    },
    body: form.toString(),
  });
}

module.exports = async (req, res) => {
  // CORS
  Object.entries(CORS).forEach(([k, v]) => res.setHeader(k, v));

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  const target = new URL(req.url, 'http://localhost').searchParams.get('url');
  if (!target) return res.status(200).send('schulki-proxy läuft ✓');

  const token = process.env.SCHULKI_TOKEN ?? '';

  try {
    // ── POST ──────────────────────────────────────────────────
    if (req.method === 'POST') {
      // Body lesen
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const bodyStr = Buffer.concat(chunks).toString();
      let human = '';
      try   { human = JSON.parse(bodyStr).human ?? ''; }
      catch { human = new URLSearchParams(bodyStr).get('human') ?? bodyStr; }

      // CSRF holen falls noch nicht vorhanden
      if (!csrfToken) await fetchCsrf();

      let upstream = await doPost(target, human);

      // Bei 419 → CSRF neu holen und nochmals versuchen
      if (upstream.status === 419) {
        console.log('419 → CSRF erneuern...');
        csrfToken = null;
        await fetchCsrf();
        upstream = await doPost(target, human);
      }

      const ct = upstream.headers.get('content-type') ?? 'application/json';
      res.setHeader('Content-Type', ct);
      res.status(upstream.status);
      const data = await upstream.text();
      return res.send(data);
    }

    // ── GET / SSE ──────────────────────────────────────────────
    const upstream = await fetch(target, {
      method: 'GET',
      headers: {
        'Accept':        'text/event-stream',
        'Authorization': `Bearer ${token}`,
        'User-Agent':    'Mozilla/5.0',
        'Referer':       'https://schulki.de/',
      },
    });

    res.setHeader('Content-Type',      upstream.headers.get('content-type') ?? 'text/event-stream');
    res.setHeader('Cache-Control',     'no-cache');
    res.setHeader('X-Accel-Buffering', 'no');
    res.status(upstream.status);

    // Stream durchleiten
    upstream.body.pipe(res);

  } catch (e) {
    console.error(e);
    res.status(502).send(`Proxy-Fehler: ${e.message}`);
  }
};
