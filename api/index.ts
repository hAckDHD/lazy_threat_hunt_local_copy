import type { IncomingMessage, ServerResponse } from 'http';
import { handleRequest } from '../src/ui/server.js';

const MAX_BODY_BYTES = 6 * 1024 * 1024;

// Vercel serverless entry point: adapts Node's request/response to the
// fetch-style handler the Bun server uses.
export default async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = `https://${req.headers.host}${req.url}`;
  const body = req.method !== 'GET' && req.method !== 'HEAD'
    ? await new Promise<ArrayBuffer>(resolve => {
        const chunks: Buffer[] = [];
        let size = 0;
        req.on('data', (c: Buffer) => {
          size += c.length;
          if (size > MAX_BODY_BYTES) { req.destroy(); return; }
          chunks.push(c);
        });
        req.on('close', () => resolve(new ArrayBuffer(0)));
        req.on('end', () => {
          const buf = Buffer.concat(chunks);
          resolve(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer);
        });
      })
    : undefined;

  const webReq = new Request(url, {
    method: req.method,
    headers: req.headers as Record<string, string>,
    body: body?.byteLength ? body : undefined,
  });

  const webRes = await handleRequest(webReq);

  res.statusCode = webRes.status;
  webRes.headers.forEach((value, key) => res.setHeader(key, value));
  res.end(Buffer.from(await webRes.arrayBuffer()));
}
