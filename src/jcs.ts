// RFC 8785 JSON Canonicalization Scheme for the values E2EE v2 binds into
// AES-GCM associated data: member names sorted by UTF-16 code units, compact,
// strings and numbers in ECMAScript JSON form (which is what JCS specifies).

export function jcs(value: unknown): string {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("JCS cannot encode a non-finite number");
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, member]) => member !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, member]) => `${JSON.stringify(key)}:${jcs(member)}`).join(",")}}`;
  }
  throw new Error(`JCS cannot encode ${typeof value}`);
}
