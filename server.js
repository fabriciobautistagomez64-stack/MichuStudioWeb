
'use strict';

const express = require('express');
const http = require('node:http');
const https = require('node:https');
const path = require('node:path');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const MAIN_FILE = path.join(__dirname, 'Main.html');
const CSS_FILE = path.join(__dirname, 'Style.css');
const ACCOUNT_API = new URL(
  (process.env.ACCOUNT_API_URL || 'https://michiverse-server.onrender.com').replace(/\/+$/, '')
);

app.disable('x-powered-by');

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'michustudio',
    accountServer: ACCOUNT_API.origin
  });
});

app.get(['/', '/index.html', '/Main.html'], (_req, res) => {
  res.set('Cache-Control', 'no-cache');
  res.sendFile(MAIN_FILE, err => {
    if (err && !res.headersSent) {
      res.status(404).type('text').send('Main.html no está disponible.');
    }
  });
});

app.get(['/Style.css', '/style.css'], (_req, res) => {
  res.set('Cache-Control', 'no-cache');
  res.sendFile(CSS_FILE, err => {
    if (err && !res.headersSent) {
      res.status(404).type('text').send('Style.css no está disponible.');
    }
  });
});

app.use((req, res) => {
  const requestPath = req.originalUrl.startsWith('/')
    ? req.originalUrl
    : `/${req.originalUrl}`;

  const upstreamUrl = new URL(`${ACCOUNT_API.origin}${requestPath}`);
  const client = upstreamUrl.protocol === 'https:' ? https : http;

  const requestHeaders = {
    ...req.headers,
    host: upstreamUrl.host,
    connection: 'close'
  };

  delete requestHeaders['proxy-connection'];

  const upstreamReq = client.request(upstreamUrl, {
    method: req.method,
    headers: requestHeaders
  }, upstreamRes => {
    const responseHeaders = { ...upstreamRes.headers };

    for (const name of [
      'connection',
      'keep-alive',
      'proxy-authenticate',
      'proxy-authorization',
      'te',
      'trailer',
      'transfer-encoding',
      'upgrade'
    ]) {
      delete responseHeaders[name];
    }

    if (responseHeaders['set-cookie']) {
      const cookies = Array.isArray(responseHeaders['set-cookie'])
        ? responseHeaders['set-cookie']
        : [responseHeaders['set-cookie']];

      responseHeaders['set-cookie'] = cookies.map(cookie =>
        cookie.replace(/;\s*domain=[^;]+/ig, '')
      );
    }

    res.writeHead(upstreamRes.statusCode || 502, responseHeaders);
    upstreamRes.pipe(res);
  });

  upstreamReq.setTimeout(90000, () => {
    upstreamReq.destroy(new Error('El servidor de cuentas tardó demasiado.'));
  });

  upstreamReq.on('error', () => {
    if (!res.headersSent) {
      res.status(502).json({
        error: 'No se pudo conectar con el servidor de cuentas. Intenta de nuevo.'
      });
    } else {
      res.destroy();
    }
  });

  req.pipe(upstreamReq);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[MichuStudio] Web lista en el puerto ${PORT}; API: ${ACCOUNT_API.origin}`);
});
