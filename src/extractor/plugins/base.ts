import type { IOC, IOCType } from '../../types/index.js';

export interface ExtractorPlugin {
  name: string;
  supportedTypes: IOCType[];
  // Return additional IOCs found through plugin-specific logic (e.g., STIX parsing, threat feed formats)
  extract(text: string, baseIOCs: IOC[]): IOC[];
  // Optionally post-process IOCs after base extraction
  postProcess?(iocs: IOC[]): IOC[];
}

export abstract class BasePlugin implements ExtractorPlugin {
  abstract name: string;
  abstract supportedTypes: IOCType[];
  abstract extract(text: string, baseIOCs: IOC[]): IOC[];

  protected makeId(): string {
    return Math.random().toString(36).slice(2) + Date.now().toString(36);
  }
}
