import { readFile } from 'fs/promises';
import { extname } from 'path';
import { extract } from '../extractor/index.js';
import { parseCSVText, parseJSONFeed } from './manual.js';
import type { ExtractionResult } from '../types/index.js';

export async function parseFile(filePath: string): Promise<ExtractionResult> {
  const ext = extname(filePath).toLowerCase();
  const source = 'file' as const;
  const tags = ['file-import'];

  switch (ext) {
    case '.txt':
    case '.log':
    case '.ioc': {
      const text = await readFile(filePath, 'utf-8');
      return extract(text, { source, sourceFile: filePath, tags });
    }

    case '.csv': {
      const text = await readFile(filePath, 'utf-8');
      const result = parseCSVText(text);
      return { ...result, sourceFile: filePath };
    }

    case '.json':
    case '.stix':
    case '.jsonl': {
      const text = await readFile(filePath, 'utf-8');
      const result = parseJSONFeed(text);
      return { ...result, sourceFile: filePath };
    }

    case '.pdf':
      return parsePDF(filePath);

    case '.docx':
    case '.doc':
      return parseDOCX(filePath);

    case '.md':
    case '.markdown': {
      const text = await readFile(filePath, 'utf-8');
      // Strip markdown syntax
      const plain = text
        .replace(/```[\s\S]*?```/g, ' ')
        .replace(/`[^`]+`/g, ' ')
        .replace(/#{1,6}\s/g, '')
        .replace(/\*\*?([^*]+)\*\*?/g, '$1')
        .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1 ');
      return extract(plain, { source, sourceFile: filePath, tags });
    }

    default:
      throw new Error(`Unsupported file type: ${ext}`);
  }
}

async function parsePDF(filePath: string): Promise<ExtractionResult> {
  try {
    // Dynamic import so the module is optional
    const pdfParse = (await import('pdf-parse')).default;
    const buf = await readFile(filePath);
    const data = await pdfParse(buf);
    return extract(data.text, {
      source: 'file',
      sourceFile: filePath,
      tags: ['pdf'],
    });
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === 'MODULE_NOT_FOUND' ||
        (err as Error).message?.includes('Cannot find')) {
      throw new Error('PDF parsing requires: bun add pdf-parse');
    }
    throw err;
  }
}

async function parseDOCX(filePath: string): Promise<ExtractionResult> {
  try {
    const mammoth = (await import('mammoth')).default;
    const result = await mammoth.extractRawText({ path: filePath });
    return extract(result.value, {
      source: 'file',
      sourceFile: filePath,
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

// Parse raw buffer with explicit mime type
export async function parseBuffer(
  buf: Buffer,
  mimeType: string,
  filename: string
): Promise<ExtractionResult> {
  const tmpExt = mimeTypeToExt(mimeType) ?? extname(filename);
  const tmpPath = `/tmp/ioc_upload_${Date.now()}${tmpExt}`;
  await Bun.write(tmpPath, buf);
  return parseFile(tmpPath);
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
