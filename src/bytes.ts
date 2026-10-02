// Byte helpers for NATION Incognito. Web Crypto only, so the same code runs in
// the browser, the server and the CLI.

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export const utf8 = (text: string): Uint8Array => encoder.encode(text);
export const fromUtf8 = (bytes: Uint8Array): string => decoder.decode(bytes);

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

/** Hex (either case, optional `0x`) to bytes; throws on anything else. */
export function fromHex(hex: string): Uint8Array {
  const value = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (value.length % 2 || !/^[0-9a-fA-F]*$/.test(value)) throw new Error("invalid hex");
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/** Web Crypto wants an ArrayBuffer-backed view; a copy keeps every caller honest. */
export const buffer = (bytes: Uint8Array): ArrayBuffer => bytes.slice().buffer as ArrayBuffer;

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(bytes))));
}

/** Incremental byte sink: keeps the exact wire bytes of a streamed body. */
export class ByteLog {
  private parts: Uint8Array[] = [];
  length = 0;
  push(chunk: Uint8Array): void { this.parts.push(chunk); this.length += chunk.length; }
  bytes(): Uint8Array { return concat(...this.parts); }
}
