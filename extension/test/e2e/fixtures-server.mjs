// Les pages de test (test/fixtures/) servies sur leur propre origine, distincte de celle de l'app :
// un site quelconque, comme ceux que l'extension rencontre. Port libre choisi par le système,
// ou FIXTURES_PORT.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = resolve(fileURLToPath(new URL('../fixtures', import.meta.url)));
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.png': 'image/png',
};

export async function serveFixtures() {
  const server = createServer(async (req, res) => {
    let file;
    try {
      file = resolve(DIR, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname));
    } catch {
      file = null;
    }
    if (!file || !file.startsWith(DIR + sep)) {
      res.writeHead(403).end('Interdit');
      return;
    }
    try {
      const body = await readFile(file);
      res.writeHead(200, { 'Content-Type': TYPES[extname(file).toLowerCase()] || 'application/octet-stream', 'Cache-Control': 'no-store' });
      res.end(body);
    } catch {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Introuvable');
    }
  });
  await new Promise((ok) => server.listen(Number(process.env.FIXTURES_PORT) || 0, '127.0.0.1', ok));
  return {
    url: `http://localhost:${server.address().port}`,
    close: () => new Promise((ok) => server.close(ok)),
  };
}
