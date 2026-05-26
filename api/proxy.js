console.log('ENV:', JSON.stringify(process.env.SCHULKI_TOKEN));
// api/proxy.js  –  Vercel Serverless Function
const nodeFetch   = require('node-fetch');
const fetchCookie = require('fetch-cookie');
const { CookieJar } = require('tough-cookie');

// Persistente Cookie-Jar – genau wie der Python-Proxy
const jar   = new CookieJar();
const fetch = fetchCookie(nodeFetch, jar);
let csrfToken = null;

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Accept, Content-Type',
};

async function fetchCsrf() {
  try {
    jar.removeAllCookiesSync();
    csrfToken = null;

    const res  = await fetch('https://schulki.de/login', {
      headers: { 'User-Agent': 'Mozilla/5.0', 'Referer': 'https://schulki.de/' },
    });
    const html = await res.text();

    // CSRF aus Meta-Tag
    const metaMatch = html.match(/name=["']csrf-token["'][^>]+content=["']([^"']+)["']/);
    if (metaMatch) {
      csrfToken = metaMatch[1];
      console.log('CSRF (meta):', csrfToken.slice(0, 20));
      return;
    }

    // CSRF aus Cookie-Jar
    const cookies = await jar.getCookies('https://schulki.de');
    const xsrf    = cookies.find(c => c.key === 'XSRF-TOKEN');
    if (xsrf) {
      csrfToken = decodeURIComponent(xsrf.value);
      console.log('CSRF (cookie):', csrfToken.slice(0, 20));
    }
  } catch (e) {
    console.error('fetchCsrf Fehler:', e.message);
  }
}

async function doPost(target, human, bearerToken) {
  const form = new URLSearchParams({ human, _token: csrfToken ?? '' });
  return fetch(target, {
    method: 'POST',
    headers: {
      'Content-Type':  'application/x-www-form-urlencoded',
      'Accept':        'application/json',
      'Authorization': `Bearer ${bearerToken}`,
      'X-CSRF-TOKEN':  csrfToken ?? '',
      'User-Agent':    'Mozilla/5.0',
      'Referer':       'https://schulki.de/',
    },
    body: form.toString(),
  });
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString();
}

const handler = async (req, res) => {
  Object.entries(CORS).forEach(([k, v]) => res.setHeader(k, v));

  if (req.method === 'OPTIONS') return res.status(204).end();

  const target = new URL(req.url, 'http://localhost').searchParams.get('url');
  if (!target) return res.status(200).send('schulki-proxy läuft ✓');

  const bearerToken = process.env.SCHULKI_TOKEN ?? '';

  try {
    // ── POST ────────────────────────────────────────────────
    if (req.method === 'POST') {
      const bodyStr = await readBody(req);
      console.log('Body empfangen:', bodyStr.slice(0, 100));

      let human = '';
      try   { human = JSON.parse(bodyStr).human ?? ''; }
      catch { human = new URLSearchParams(bodyStr).get('human') ?? ''; }

      console.log('human:', JSON.stringify(human));
      console.log('token:', bearerToken ? bearerToken.slice(0,8)+'...' : 'LEER!');

      if (!csrfToken) await fetchCsrf();

      let upstream = await doPost(target, human, bearerToken);

      // 419 → CSRF erneuern und nochmals versuchen
      if (upstream.status === 419) {
        console.log('419 → CSRF erneuern...');
        await fetchCsrf();
        upstream = await doPost(target, human, bearerToken);
      }

      const ct   = upstream.headers.get('content-type') ?? 'application/json';
      const data = await upstream.text();
      console.log('Antwort status:', upstream.status, 'data:', data.slice(0, 100));
      res.setHeader('Content-Type', ct);
      return res.status(upstream.status).send(data);
    }

    // ── GET / SSE ──────────────────────────────────────────
    const upstream = await nodeFetch(target, {
      method: 'GET',
      headers: {
        'Accept':        'text/event-stream',
        'Authorization': `Bearer ${bearerToken}`,
        'User-Agent':    'Mozilla/5.0',
        'Referer':       'https://schulki.de/',
      },
    });

    res.setHeader('Content-Type',      upstream.headers.get('content-type') ?? 'text/event-stream');
    res.setHeader('Cache-Control',     'no-cache');
    res.setHeader('X-Accel-Buffering', 'no');
    res.status(upstream.status);
    upstream.body.pipe(res);

  } catch (e) {
    console.error(e);
    res.status(502).send(`Proxy-Fehler: ${e.message}`);
  }
};

handler.config = { api: { bodyParser: false } };
module.exports = handler;
