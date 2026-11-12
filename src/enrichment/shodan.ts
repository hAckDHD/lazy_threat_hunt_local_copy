import type { IOC, IOCEnrichment } from '../types/index.js';

const BASE = 'https://api.shodan.io';

export async function enrichWithShodan(
  ioc: IOC,
  apiKey: string
): Promise<IOCEnrichment | null> {
  if (ioc.type !== 'ip' && ioc.type !== 'ipv6') return null;

  try {
    const res = await fetch(
      `${BASE}/shodan/host/${encodeURIComponent(ioc.value)}?key=${apiKey}`
    );

    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`Shodan API ${res.status}`);

    const json = (await res.json()) as ShodanResponse;
    return parseResponse(json);
  } catch (err) {
    console.error(`[Shodan] enrichment failed for ${ioc.value}:`, err);
    return null;
  }
}

interface ShodanResponse {
  country_code?: string;
  city?: string;
  asn?: string;
  org?: string;
  latitude?: number;
  longitude?: number;
  tags?: string[];
  ports?: number[];
  last_update?: string;
  isp?: string;
}

function parseResponse(json: ShodanResponse): IOCEnrichment {
  return {
    provider: 'shodan',
    country: json.country_code,
    city: json.city,
    asn: json.asn,
    asnOrg: json.org ?? json.isp,
    latitude: json.latitude,
    longitude: json.longitude,
    lastSeen: json.last_update,
    raw: {
      ports: json.ports,
      tags: json.tags,
    },
  };
}
