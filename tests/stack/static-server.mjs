// Minimal GitHub Pages emulation for LOCAL checks of built artifacts:
// - /dir  -> 301 /dir/ (query preserved; the fragment never reaches a server)
// - /dir/ -> /dir/index.html, /name -> /name.html when present
// - unknown paths -> /404.html with status 404 (the site's SPA fallback, if any)
// It sets no security headers, like Pages; header-level guarantees are not implied.
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, resolve } from 'node:path';

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.json': 'application/json', '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml', '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json', '.wasm': 'application/wasm',
};

export function startStaticServer({ root, port }) {
  const base = resolve(root);
  const log = [];
  const isFile = async p => { try { return (await stat(p)).isFile(); } catch { return false; } };
  const isDir = async p => { try { return (await stat(p)).isDirectory(); } catch { return false; } };
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, `http://127.0.0.1:${port}`);
    log.push({ method: req.method, path: url.pathname, hasQuery: url.search.length > 0 });
    let path;
    try { path = decodeURIComponent(url.pathname); } catch { res.writeHead(400).end(); return; }
    const target = normalize(join(base, path));
    if (!target.startsWith(base)) { res.writeHead(403).end(); return; }
    let file = null;
    if (await isDir(target)) {
      if (!url.pathname.endsWith('/')) {
        res.writeHead(301, { Location: `${url.pathname}/${url.search}` }).end();
        return;
      }
      if (await isFile(join(target, 'index.html'))) file = join(target, 'index.html');
    } else if (await isFile(target)) file = target;
    else if (await isFile(`${target}.html`)) file = `${target}.html`;
    let status = 200;
    if (!file) {
      status = 404;
      file = (await isFile(join(base, '404.html'))) ? join(base, '404.html') : null;
    }
    if (!file) { res.writeHead(404, { 'Content-Type': 'text/plain' }).end('404'); return; }
    res.writeHead(status, { 'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream', 'Cache-Control': 'max-age=600' });
    res.end(req.method === 'HEAD' ? undefined : await readFile(file));
  });
  return new Promise(r => server.listen(port, '127.0.0.1', () => r({ server, log })));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [root, port] = process.argv.slice(2);
  await startStaticServer({ root, port: Number(port) });
  console.log(`serving ${root} on http://127.0.0.1:${port}`);
}
