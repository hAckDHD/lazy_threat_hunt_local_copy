// Derive the username forms an email IOC may appear as in authentication,
// sign-in, and account telemetry. Most directories use the full address as the
// UPN/login name, while legacy AD (sAMAccountName) and *nix accounts use just
// the local part. Returning both (deduped, order-preserving) lets an email hunt
// pivot into identity logs regardless of which convention the environment uses.
//
// Per-language quoting/escaping is still the caller's responsibility — this only
// decides *which* values to match, not how to template them.
export function emailUsernames(emails: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const email of emails) {
    const at = email.indexOf('@');
    const candidates = at > 0 ? [email, email.slice(0, at)] : [email];
    for (const c of candidates) {
      if (c && !seen.has(c)) {
        seen.add(c);
        out.push(c);
      }
    }
  }
  return out;
}
