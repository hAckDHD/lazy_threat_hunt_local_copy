import type { ExtractorPlugin } from './base.js';
import type { IOC, IOCType } from '../../types/index.js';

const plugins: ExtractorPlugin[] = [];

export function registerPlugin(plugin: ExtractorPlugin): void {
  plugins.push(plugin);
}

export function getPlugins(): ExtractorPlugin[] {
  return [...plugins];
}

export function runPlugins(text: string, baseIOCs: IOC[]): IOC[] {
  const additional: IOC[] = [];
  for (const plugin of plugins) {
    try {
      const found = plugin.extract(text, baseIOCs);
      additional.push(...found);
    } catch (err) {
      console.error(`Plugin ${plugin.name} failed:`, err);
    }
  }
  return additional;
}

export function postProcessWithPlugins(iocs: IOC[]): IOC[] {
  let result = [...iocs];
  for (const plugin of plugins) {
    if (plugin.postProcess) {
      try {
        result = plugin.postProcess(result);
      } catch (err) {
        console.error(`Plugin ${plugin.name} postProcess failed:`, err);
      }
    }
  }
  return result;
}
