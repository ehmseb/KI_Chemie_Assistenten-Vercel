const express    = require('express');
const path       = require('path');
const nodeFetch  = require('node-fetch');
const fetchCookie = require('fetch-cookie');
const { CookieJar } = require('tough-cookie');

const app   = express();
const TOKEN = process.env.SCHULKI_TOKEN;

// Persistente Cookie-Jar für CSRF – genau wie der Python-Proxy
const jar   = new CookieJar();
const fetch = fetchCookie(nodeFetch, jar);
let csrfToken = null;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

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
    const m = html.match(/name=["']csrf-token["'][^>]+content=["']([^"']+)["']/);
    if (m) { csrfToken = m[1]; console.log('CSRF (meta):', csrfToken.slice(0,20)); return; }
    const cookies = await jar.getCookies('https://schulki.de');
    const xsrf    = cookies.find(c => c.key === 'XSRF-TOKEN');
    if (xsrf) { csrfToken = decodeURIComponent(xsrf.value); console.log('CSRF (cookie):', csrfToken.slice(0,20)); }
  } catch (e) { console.error('fetchCsrf:', e.message); }
}

// Proxy-Route
app.all('/proxy', async (req, res) => {
  Object.entries(CORS).forEach(([k, v]) => res.setHeader(k, v));
  if (req.method === 'OPTIONS') return res.status(204).end();

  const target = req.query.url;
  if (!target) return res.status(200).send('schulki-proxy läuft ✓');

  try {
    if (req.method === 'POST') {
      const human = req.body?.human ?? '';
      if (!csrfToken) await fetchCsrf();

      const doPost = () => {
        const form = new URLSearchParams({ human, _token: csrfToken ?? '' });
        return fetch(target, {
          method: 'POST',
          headers: {
            'Content-Type':  'application/x-www-form-urlencoded',
            'Accept':        'application/json',
            'Authorization': `Bearer ${TOKEN}`,
            'X-CSRF-TOKEN':  csrfToken ?? '',
            'User-Agent':    'Mozilla/5.0',
            'Referer':       'https://schulki.de/',
          },
          body: form.toString(),
        });
      };

      let upstream = await doPost();
      if (upstream.status === 419) {
        console.log('419 → CSRF erneuern...');
        await fetchCsrf();
        upstream = await doPost();
      }

      const ct   = upstream.headers.get('content-type') ?? 'application/json';
      const data = await upstream.text();
      res.setHeader('Content-Type', ct);
      return res.status(upstream.status).send(data);
    }

    // GET / SSE
    const upstream = await nodeFetch(target, {
      method: 'GET',
      headers: {
        'Accept':        'text/event-stream',
        'Authorization': `Bearer ${TOKEN}`,
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
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`schulki-proxy läuft auf Port ${PORT}`));
