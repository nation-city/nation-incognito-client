// ACI E2EE v2, the X25519 suite (Dstack-TEE/private-ai-gateway spec/e2ee-v2.md,
// frozen; supported by the reference gateway through at least 2027-02-10).
//
// Every content-bearing request field is sealed to the service key that the
// attested workload keyset lists; every generated response field comes back
// sealed to a fresh per-request client key. Each field is
//
//   hex( ephemeral X25519 public key (32) || AES-GCM nonce (12) || ciphertext || tag (16) )
//
// keyed by HKDF-SHA256(salt = none, ikm = X25519 shared secret,
// info = "aci.e2ee.v2.x25519") and bound by AES-GCM associated data to the
// field path, the model, and the request nonce and timestamp (JCS, §6).
//
// Nothing between this process and the enclave (the NATION gateway included)
// can read or rewrite a field. What stays visible: the model id, sizes,
// timing, token counts, and the message structure.
import { buffer, concat, fromHex, fromUtf8, randomBytes, toHex, utf8 } from "./bytes.ts";
import { jcs } from "./jcs.ts";

export const E2EE_VERSION = "2";
export const X25519_SUITE = "x25519-aes-256-gcm-hkdf-sha256";
const HKDF_INFO = utf8("aci.e2ee.v2.x25519");
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
/** The smallest sealed field: an empty plaintext still carries key, nonce and tag. */
export const MIN_SEALED_HEX = (KEY_BYTES + IV_BYTES + TAG_BYTES) * 2;

export const E2EE_HEADERS = {
  version: "X-E2EE-Version",
  clientKey: "X-Client-Pub-Key",
  modelKey: "X-Model-Pub-Key",
  nonce: "X-E2EE-Nonce",
  timestamp: "X-E2EE-Timestamp",
} as const;

export class E2eeError extends Error {}

/** Web Crypto key pair (spelled out: the server build has no DOM lib). */
type KeyPair = { publicKey: CryptoKey; privateKey: CryptoKey };

export interface ChatContentPart { type: string; text?: string; image_url?: { url: string }; [key: string]: unknown }
export interface ChatMessage { role: string; content: string | ChatContentPart[] | null; [key: string]: unknown }
export interface ChatRequestBody { model: string; messages: ChatMessage[]; [key: string]: unknown }

/** True when the runtime's Web Crypto can do X25519 (every current browser and Node 20+). */
export async function x25519Supported(): Promise<boolean> {
  try {
    await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
    return true;
  } catch {
    return false;
  }
}

async function importPublic(hex: string): Promise<CryptoKey> {
  const raw = fromHex(hex);
  if (raw.length !== KEY_BYTES) throw new E2eeError("X25519 public key must be 32 bytes");
  return crypto.subtle.importKey("raw", buffer(raw), { name: "X25519" }, true, []);
}

async function fieldKey(privateKey: CryptoKey, publicKey: CryptoKey, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  const shared = await crypto.subtle.deriveBits({ name: "X25519", public: publicKey }, privateKey, 256);
  const ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: buffer(HKDF_INFO) },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

/** Seal one field to a recipient's X25519 public key with a fresh ephemeral key. */
export async function sealField(plaintext: Uint8Array, recipientPublicHex: string, aad: Uint8Array): Promise<string> {
  const recipient = await importPublic(recipientPublicHex);
  const ephemeral = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as unknown as KeyPair;
  const key = await fieldKey(ephemeral.privateKey, recipient, "encrypt");
  const iv = randomBytes(IV_BYTES);
  const sealed = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: buffer(iv), additionalData: buffer(aad), tagLength: TAG_BYTES * 8 }, key, buffer(plaintext)));
  const ephemeralRaw = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
  return toHex(concat(ephemeralRaw, iv, sealed));
}

/** Open one sealed field with the recipient's private key; throws unless the tag and AAD verify. */
export async function openField(sealedHex: string, privateKey: CryptoKey, aad: Uint8Array): Promise<Uint8Array> {
  if (typeof sealedHex !== "string" || sealedHex.length < MIN_SEALED_HEX || !/^[0-9a-fA-F]+$/.test(sealedHex)) {
    throw new E2eeError("field is not E2EE v2 ciphertext");
  }
  const bytes = fromHex(sealedHex);
  const ephemeral = await importPublic(toHex(bytes.subarray(0, KEY_BYTES)));
  const key = await fieldKey(privateKey, ephemeral, "decrypt");
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buffer(bytes.subarray(KEY_BYTES, KEY_BYTES + IV_BYTES)), additionalData: buffer(aad), tagLength: TAG_BYTES * 8 },
      key,
      buffer(bytes.subarray(KEY_BYTES + IV_BYTES)),
    ));
  } catch {
    throw new E2eeError("field failed authentication");
  }
}

export interface AadContext { model: string; nonce: string; timestamp: number }

export const requestAad = (ctx: AadContext, field: string): Uint8Array => utf8(jcs({
  purpose: "aci.e2ee.request.v2", algo: X25519_SUITE, model: ctx.model, field, nonce: ctx.nonce, ts: ctx.timestamp,
}));

export const responseAad = (ctx: AadContext, id: string, field: string): Uint8Array => utf8(jcs({
  purpose: "aci.e2ee.response.v2", algo: X25519_SUITE, model: ctx.model, id, field, nonce: ctx.nonce, ts: ctx.timestamp,
}));

/** The gateway restores any decrypted whole content that parses as a JSON
 * array as structured content (§5). Text that merely looks like an array is
 * wrapped as a text part first, so the model receives exactly what was typed. */
export function normalizeContent(content: ChatMessage["content"]): ChatMessage["content"] {
  if (typeof content !== "string") return content;
  try {
    if (Array.isArray(JSON.parse(content))) return [{ type: "text", text: content }];
  } catch { /* ordinary text */ }
  return content;
}

const choiceIndex = (choice: Record<string, unknown>, position: number) =>
  typeof choice.index === "number" && Number.isSafeInteger(choice.index) && choice.index >= 0 ? choice.index : position;

const RESPONSE_FIELDS = ["content", "reasoning", "reasoning_content"] as const;
export type ResponseField = (typeof RESPONSE_FIELDS)[number];

export interface DecryptedChoice { index: number; content: string; reasoning: string; finishReason: string | null }

/** One request's E2EE state: the fresh client key pair, the replay nonce and
 * timestamp, and the attested service key every request field is sealed to. */
export interface E2eeExchange {
  readonly model: string;
  readonly nonce: string;
  readonly timestamp: number;
  readonly clientPublicKey: string;
  readonly servicePublicKey: string;
  headers(): Record<string, string>;
  /** Seal every content field. `restored` is the compact JSON the enclave
   * hashes after decrypting (the receipt's `request.received`), `wire` is what
   * actually travels. Both keep the caller's member order. */
  sealRequest(body: ChatRequestBody): Promise<{ wire: string; restored: string; sealedFields: number }>;
  /** Open every generated field of a buffered completion or one stream chunk. */
  openCompletion(json: Record<string, unknown>, kind: "message" | "delta"): Promise<DecryptedChoice[]>;
}

export async function openExchange(input: { servicePublicKey: string; model: string; now?: () => number }): Promise<E2eeExchange> {
  if (typeof input.model !== "string" || !input.model) throw new E2eeError("a model id is required");
  const servicePublicKey = toHex(fromHex(input.servicePublicKey));
  if (servicePublicKey.length !== KEY_BYTES * 2) throw new E2eeError("service key is not an X25519 key");
  const client = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as unknown as KeyPair;
  const clientPublicKey = toHex(new Uint8Array(await crypto.subtle.exportKey("raw", client.publicKey)));
  const ctx: AadContext = {
    model: input.model,
    nonce: toHex(randomBytes(32)),
    timestamp: Math.floor((input.now?.() ?? Date.now()) / 1000),
  };
  return {
    model: ctx.model,
    nonce: ctx.nonce,
    timestamp: ctx.timestamp,
    clientPublicKey,
    servicePublicKey,
    headers: () => ({
      [E2EE_HEADERS.version]: E2EE_VERSION,
      [E2EE_HEADERS.clientKey]: clientPublicKey,
      [E2EE_HEADERS.modelKey]: servicePublicKey,
      [E2EE_HEADERS.nonce]: ctx.nonce,
      [E2EE_HEADERS.timestamp]: String(ctx.timestamp),
    }),
    async sealRequest(body) {
      if (body.model !== ctx.model) throw new E2eeError("the request model must match the exchange model");
      const plain: ChatRequestBody = { ...body, messages: body.messages.map((message) => ({ ...message, content: normalizeContent(message.content) })) };
      const wire = JSON.parse(JSON.stringify(plain)) as ChatRequestBody;
      let sealedFields = 0;
      for (const [index, message] of wire.messages.entries()) {
        if (message.content === null || message.content === undefined) continue;
        const text = typeof message.content === "string" ? message.content : JSON.stringify(message.content);
        message.content = await sealField(utf8(text), servicePublicKey, requestAad(ctx, `messages.${index}.content`));
        sealedFields++;
      }
      if (!sealedFields) throw new E2eeError("nothing to encrypt: a request needs at least one message with content");
      return { wire: JSON.stringify(wire), restored: JSON.stringify(plain), sealedFields };
    },
    async openCompletion(json, kind) {
      const id = typeof json.id === "string" ? json.id : "";
      const choices = Array.isArray(json.choices) ? json.choices : [];
      const out: DecryptedChoice[] = [];
      for (const [position, raw] of choices.entries()) {
        if (!raw || typeof raw !== "object") continue;
        const choice = raw as Record<string, unknown>;
        const index = choiceIndex(choice, position);
        const holder = choice[kind];
        const decrypted: DecryptedChoice = { index, content: "", reasoning: "", finishReason: typeof choice.finish_reason === "string" ? choice.finish_reason : null };
        if (holder && typeof holder === "object") {
          const fields = holder as Record<string, unknown>;
          for (const field of RESPONSE_FIELDS) {
            const value = fields[field];
            if (value === null || value === undefined) continue;
            if (typeof value !== "string") throw new E2eeError(`response ${field} is not a sealed string`);
            const plaintext = fromUtf8(await openField(value, client.privateKey, responseAad(ctx, id, `choices.${index}.${kind}.${field}`)));
            if (field === "content") decrypted.content += plaintext;
            else decrypted.reasoning += plaintext;
          }
        }
        out.push(decrypted);
      }
      return out;
    },
  };
}

/** Splits a byte stream into SSE `data:` payloads without touching the bytes
 * themselves (the caller keeps those for the receipt's response hash). */
export class SseDataReader {
  private decoder = new TextDecoder("utf-8");
  private pending = "";
  push(chunk: Uint8Array): string[] { return this.lines(this.pending + this.decoder.decode(chunk, { stream: true }), false); }
  finish(): string[] { return this.lines(this.pending + this.decoder.decode(), true); }
  private lines(text: string, final: boolean): string[] {
    const parts = text.split("\n");
    // Mid-stream the last segment may be half a line; at the end it is whole.
    this.pending = final ? "" : parts.pop() ?? "";
    const out: string[] = [];
    for (const raw of parts) {
      const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
      if (line.startsWith("data:")) out.push(line.slice(5).trim());
    }
    return out;
  }
}
