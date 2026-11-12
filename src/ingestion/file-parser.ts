import { readFile } from 'fs/promises';
import { extname } from 'path';
import { extract } from '../extractor/index.js';
import { parseCSVText, parseJSONFeed } from './manual.js';
import type { ExtractionResult } from '../types/index.js';

// Parse a file on local disk (CLI usage).
export async function parseFile(filePath: string): Promise<ExtractionResult> {
  const buf = await readFile(filePath);
  return parseContent(buf, extname(filePath).toLowerCase(), filePath);
}

// Parse an uploaded buffer entirely in memory — no temp files are written.
export async function parseBuffer(
  buf: Buffer,
  mimeType: string,
  filename: string
): Promise<ExtractionResult> {
  const ext = mimeTypeToExt(mimeType) ?? extname(filename).toLowerCase();
  return parseContent(buf, ext, filename);
}

async function parseContent(buf: Buffer, ext: string, sourceFile: string): Promise<ExtractionResult> {
  const source = 'file' as const;
  const tags = ['file-import'];

  switch (ext) {
    case '.txt':
    case '.log':
    case '.ioc':
      return extract(buf.toString('utf-8'), { source, sourceFile, tags });

    case '.csv': {
      const result = parseCSVText(buf.toString('utf-8'));
      return { ...result, sourceFile };
    }

    case '.json':
    case '.stix':
    case '.jsonl': {
      const result = parseJSONFeed(buf.toString('utf-8'));
      return { ...result, sourceFile };
    }

    case '.pdf':
      return parsePDF(buf, sourceFile);

    case '.docx':
      return parseDOCX(buf, sourceFile);

    case '.md':
    case '.markdown': {
      // Strip markdown syntax
      const plain = buf.toString('utf-8')
        .replace(/```[\s\S]*?```/g, ' ')
        .replace(/`[^`]+`/g, ' ')
        .replace(/#{1,6}\s/g, '')
        .replace(/\*\*?([^*]+)\*\*?/g, '$1')
        .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1 ');
      return extract(plain, { source, sourceFile, tags });
    }

    default:
      throw new Error(`Unsupported file type: ${ext || '(none)'}`);
  }
}

async function parsePDF(buf: Buffer, sourceFile: string): Promise<ExtractionResult> {
  // unpdf: pure-JavaScript text extraction on a current PDF.js build. It never
  // renders pages, runs scripts or loads native code.
  const { extractText, getDocumentProxy } = await import('unpdf');
  let text: string;
  try {
    const pdf = await getDocumentProxy(new Uint8Array(buf));
    ({ text } = await extractText(pdf, { mergePages: true }));
  } catch {
    throw new Error('Unsupported file type: not a readable PDF');
  }
  return extract(text, { source: 'file', sourceFile, tags: ['pdf'] });
}

async function parseDOCX(buf: Buffer, sourceFile: string): Promise<ExtractionResult> {
  try {
    const mammoth = (await import('mammoth')).default;
    const result = await mammoth.extractRawText({ buffer: buf });
    return extract(result.value, {
      source: 'file',
      sourceFile,
      tags: ['docx'],
    });
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === 'MODULE_NOT_FOUND' ||
        (err as Error).message?.includes('Cannot find')) {
      throw new Error('DOCX parsing requires: bun add mammoth');
    }
    throw err;
  }
}

function mimeTypeToExt(mime: string): string | null {
  const map: Record<string, string> = {
    'application/pdf': '.pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
    'application/json': '.json',
    'text/plain': '.txt',
    'text/csv': '.csv',
  };
  return map[mime] ?? null;
}
