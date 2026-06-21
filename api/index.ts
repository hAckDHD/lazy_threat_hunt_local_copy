import type { VercelRequest, VercelResponse } from '@vercel/node';
import { handleRequest } from '../src/ui/server.js';

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const url = `https://${req.headers.host}${req.url}`;
  const body = req.method !== 'GET' && req.method !== 'HEAD'
    ? await new Promise<ArrayBuffer>(resolve => {
        const chunks: Buffer[] = [];
        req.on('data', (c: Buffer) => chunks.push(c));
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

  res.status(webRes.status);
  webRes.headers.forEach((value, key) => res.setHeader(key, value));
  res.end(Buffer.from(await webRes.arrayBuffer()));
}
