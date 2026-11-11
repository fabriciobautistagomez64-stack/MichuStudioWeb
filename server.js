'use strict';

const express = require('express');
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const MAIN_FILE = path.join(__dirname, 'Main.html');
const STYLE_FILE = path.join(__dirname, 'Style.css');
const GAMES_FILE = path.join(__dirname, 'Juegos.json');
const PHOTOS_DIR = path.join(__dirname, 'Photos');
const MICHIVERSE_IMAGES_DIR = path.join(PHOTOS_DIR, 'imágenes');
const MICHIVERSE_IMAGES_FOLDER = 'imágenes';
const IMAGE_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.webp', '.avif', '.gif']);

fs.mkdirSync(MICHIVERSE_IMAGES_DIR, { recursive: true });

const ACCOUNT_API = new URL(
  (process.env.ACCOUNT_API_URL || 'https://michiverse-server.onrender.com').replace(/\/+$/, '')
);
const FORUM_API = new URL(
  (process.env.FORUM_API_URL || 'https://michustudioforum.onrender.com').replace(/\/+$/, '')
);

app.disable('x-powered-by');

// Render entrega el IP real del visitante en CF-Connecting-IP.
// Ese valor se reenvía como un único X-Forwarded-For para que los
// backends que usan Express trust proxy = 1 limiten por visitante,
// y no por la IP compartida del proxy de MichuStudio.
function getVerifiedClientIp(req) {
  const cloudflareIp = String(req.headers['cf-connecting-ip'] || '').trim();

  if (net.isIP(cloudflareIp)) {
    return { address: cloudflareIp, source: 'cf-connecting-ip' };
  }

  const socketIp = String(req.socket?.remoteAddress || '').trim();

  if (net.isIP(socketIp)) {
    return { address: socketIp, source: 'socket-fallback' };
  }

  return { address: 'unknown', source: 'unavailable' };
}

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'michustudio',
    accountServer: ACCOUNT_API.origin,
    forumServer: FORUM_API.origin,
    photosDirectory: 'Photos',
    michiverseImagesDirectory: 'Photos/imágenes',
    gamesFile: 'Juegos.json',
    clientIpForwarding: 'CF-Connecting-IP -> X-Forwarded-For'
  });
});

app.get(['/', '/index.html', '/Main.html'], (_req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.set('Cache-Control', 'no-store, max-age=0');
  res.sendFile(MAIN_FILE, err => {
    if (err && !res.headersSent) {
      res.status(404).type('text').send('Main.html no está disponible.');
    }
  });
});

app.get('/Style.css', (_req, res) => {
  res.setHeader('Content-Type', 'text/css; charset=utf-8');
  res.set('Cache-Control', 'no-store, max-age=0');
  res.type('text/css');
  res.sendFile(STYLE_FILE, err => {
    if (err && !res.headersSent) {
      res.status(404).type('text').send('Style.css no está disponible.');
    }
  });
});

app.get(['/Juegos.json', '/juegos.json'], (_req, res) => {
  if (!fs.existsSync(GAMES_FILE)) {
    return res.status(404).json({ error: 'Juegos.json no está disponible.' });
  }

  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.set('Cache-Control', 'no-store, max-age=0');
  res.type('application/json');
  res.sendFile(GAMES_FILE, err => {
    if (err && !res.headersSent) {
      res.status(404).json({ error: 'No se pudo leer Juegos.json.' });
    }
  });
});

// Lista las capturas de Michiverse que están directamente dentro de Photos/imágenes.
app.get('/api/michiverse-images', async (_req, res) => {
  try {
    const entries = await fs.promises.readdir(MICHIVERSE_IMAGES_DIR, { withFileTypes: true });
    const images = entries
      .filter(entry =>
        entry.isFile() &&
        !entry.name.startsWith('.') &&
        IMAGE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())
      )
      .sort((a, b) => a.name.localeCompare(b.name, 'es'))
      .map(entry => {
        const extension = path.extname(entry.name);
        const label = entry.name
          .slice(0, -extension.length)
          .replace(/[_-]+/g, ' ')
          .replace(/\s+/g, ' ')
          .trim();

        return {
          name: entry.name,
          label: label || 'Captura de Michiverse',
          url: `/Photos/${encodeURIComponent(MICHIVERSE_IMAGES_FOLDER)}/${encodeURIComponent(entry.name)}`
        };
      });

    res.set('Cache-Control', 'no-store, max-age=0');
    res.json({ images });
  } catch (error) {
    console.error('[MichuStudio] No se pudo leer Photos/imágenes:', error.message);
    res.status(500).json({ error: 'No se pudo leer la carpeta Photos/imágenes.' });
  }
});

app.use('/Photos', express.static(PHOTOS_DIR, {
  dotfiles: 'deny',
  fallthrough: true,
  index: false,
  redirect: false,
  maxAge: '1h',
  setHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
  }
}));
app.use('/Photos', (_req, res) => {
  res.status(404).json({ error: 'La imagen no existe dentro de la carpeta Photos.' });
});

app.get(['/admin', '/admin.html'], (_req, res) => {
  const file = path.join(__dirname, 'admin.html');
  if (!fs.existsSync(file)) {
    return res.status(404).type('text').send('Panel de administración no disponible.');
  }

  res.sendFile(file, err => {
    if (err && !res.headersSent) {
      res.status(404).type('text').send('Panel de administración no disponible.');
    }
  });
});

function retryAfterDelay(value) {
  if (Array.isArray(value)) value = value[0];
  if (value === undefined || value === null || value === '') return null;

  const seconds = Number(value);
  let delay;

  if (Number.isFinite(seconds)) {
    delay = seconds * 1000;
  } else {
    const date = Date.parse(String(value));
    if (!Number.isFinite(date)) return null;
    delay = date - Date.now();
  }

  // No mantener una petición abierta indefinidamente si el upstream pide esperar demasiado.
  if (delay > 30000) return null;
  return Math.max(250, delay);
}

function proxyTo(target, { stripPrefix = '', label = 'cuentas', retry429 = true } = {}) {
  return (req, res) => {
    let requestPath = req.originalUrl;

    if (stripPrefix) {
      requestPath = requestPath.replace(new RegExp('^' + stripPrefix + '(?=/|\\?|$)'), '') || '/';
    }

    if (!requestPath.startsWith('/')) requestPath = '/' + requestPath;

    let upstreamUrl;
    try {
      upstreamUrl = new URL(requestPath, target);
    } catch {
      return res.status(400).json({ error: 'La ruta solicitada no es válida.' });
    }

    const client = upstreamUrl.protocol === 'https:' ? https : http;
    const clientIp = getVerifiedClientIp(req);
    const requestHeaders = {
      ...req.headers,
      host: upstreamUrl.host,
      connection: 'close'
    };

    // No confiar en una cadena X-Forwarded-For recibida tal cual.
    // Cloudflare normaliza el IP del visitante en CF-Connecting-IP.
    requestHeaders['x-forwarded-for'] = clientIp.address;
    requestHeaders['x-real-ip'] = clientIp.address;
    delete requestHeaders['cf-connecting-ip'];
    delete requestHeaders.forwarded;
    delete requestHeaders['proxy-connection'];

    const hasRequestBody = req.method !== 'GET' && req.method !== 'HEAD';
    const canRetry429 =
      retry429 &&
      !hasRequestBody &&
      !req.headers['content-length'] &&
      !req.headers['transfer-encoding'];

    let attempts = 0;
    let retryTimer = null;
    let clientClosed = false;

    const clearRetryTimer = () => {
      if (retryTimer !== null) {
        clearTimeout(retryTimer);
        retryTimer = null;
      }
    };

    const fail = () => {
      clearRetryTimer();

      if (!res.headersSent && !res.destroyed) {
        res.status(502).json({
          error: 'No se pudo conectar con el servidor remoto. Intenta de nuevo.'
        });
      } else if (!res.destroyed) {
        res.destroy();
      }
    };

    res.on('close', () => {
      clientClosed = true;
      clearRetryTimer();
    });

    req.on('aborted', () => {
      clientClosed = true;
      clearRetryTimer();
    });

    const send = () => {
      if (clientClosed || res.destroyed) return;

      attempts += 1;

      const upstreamReq = client.request(upstreamUrl, {
        method: req.method,
        headers: requestHeaders
      }, upstreamRes => {
        const statusCode = upstreamRes.statusCode || 502;

        // Solo reintenta lecturas seguras; nunca duplica POST, PUT, PATCH ni DELETE.
        if (statusCode === 429 && canRetry429 && attempts === 1) {
          const delay = retryAfterDelay(upstreamRes.headers['retry-after']);

          if (delay !== null) {
            upstreamRes.resume();
            retryTimer = setTimeout(() => {
              retryTimer = null;
              send();
            }, delay);
            return;
          }
        }

        const responseHeaders = { ...upstreamRes.headers };

        for (const name of [
          'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
          'te', 'trailer', 'transfer-encoding', 'upgrade'
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

        responseHeaders['x-michustudio-proxy'] = 'michustudio';
        responseHeaders['x-michustudio-upstream'] = label;
        responseHeaders['x-michustudio-retries'] = String(attempts - 1);
        responseHeaders['x-michustudio-client-ip-source'] = clientIp.source;

        if (statusCode === 429) {
          console.warn(
            '[MichuStudio] HTTP 429 desde ' + label +
            ' en ' + req.method + ' ' + upstreamUrl.pathname +
            ' (reintentos: ' + (attempts - 1) + '; Retry-After: ' +
            String(upstreamRes.headers['retry-after'] || 'no indicado') +
            '; IP: ' + clientIp.source + ')'
          );
        }

        res.writeHead(statusCode, responseHeaders);
        upstreamRes.pipe(res);
      });

      upstreamReq.setTimeout(90000, () => {
        upstreamReq.destroy(new Error('El servidor remoto tardó demasiado.'));
      });

      upstreamReq.on('error', fail);

      if (hasRequestBody) {
        req.pipe(upstreamReq);
      } else {
        req.resume();
        upstreamReq.end();
      }
    };

    send();
  };
}

// Las rutas /forum/... se envían al servicio del foro quitando el prefijo /forum.
app.use('/forum', proxyTo(FORUM_API, { stripPrefix: '/forum', label: 'foro' }));

// Las demás rutas de API se envían al servidor de cuentas.
app.use(proxyTo(ACCOUNT_API, { label: 'cuentas' }));

app.listen(PORT, '0.0.0.0', () => {
  console.log(
    `[MichuStudio] Web lista en el puerto ${PORT}; ` +
    `cuentas: ${ACCOUNT_API.origin}; foro: ${FORUM_API.origin}; ` +
    `imágenes: /Photos/imágenes; juegos: /Juegos.json`
  );
});
