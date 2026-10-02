// The NATION Incognito client: verify → encrypt → send → decrypt → check the
// signed receipt. Runs wherever the person is — the browser tab, the desktop
// app, a terminal agent — so plaintext never reaches the NATION gateway,
// which only relays ciphertext to the confidential gateway and meters tokens.
import { ByteLog, utf8 } from "./bytes.ts";
import { type ChatMessage, type ChatRequestBody, E2eeError, openExchange, SseDataReader } from "./e2ee.ts";
import {
  auditReceipt, establishIdentity, identityFresh, IncognitoVerificationError, PHALA_ACI_ORIGIN,
  type IdentityPolicy, type IncognitoIdentity, type ReceiptAudit, type Verifier,
} from "./verify.ts";

export type IncognitoStep = "attest" | "encrypt" | "send" | "decrypt" | "verify";
export const INCOGNITO_STEPS: readonly IncognitoStep[] = ["attest", "encrypt", "send", "decrypt", "verify"];
export interface StepEvent { step: IncognitoStep; status: "active" | "done" | "failed"; detail?: string }

export class IncognitoRequestError extends Error {
  readonly status: number;
  readonly type?: string;
  constructor(message: string, status: number, type?: string) {
    super(message);
    this.status = status;
    if (type) this.type = type;
  }
}

export interface IncognitoClientOptions {
  /** The NATION gateway, e.g. `https://api.thenation.city/api/v1/incognito`. */
  gatewayURL: string;
  /** Extra request headers (the CLI sends `Authorization: Bearer <your NATION API key>`). */
  headers?: Record<string, string>;
  /** Browser sessions ride the same-origin cookie. */
  credentials?: "omit" | "same-origin" | "include";
  fetch?: typeof fetch;
  /** Where the attestation report and attested sessions are fetched from. */
  attestationOrigin?: string;
  policy?: IdentityPolicy;
  /** Injected only by tests; production always uses @phala/aci-verifier. */
  verifier?: Verifier;
  now?: () => number;
}

export interface IncognitoChatInput {
  model: string;
  messages: ChatMessage[];
  maxTokens?: number;
  temperature?: number;
  /** Stream decrypted text as it arrives (default). The receipt is checked
   * after the last byte. Buffered replies are verified before decryption. */
  stream?: boolean;
  /** Throw instead of returning an unverified reply. A buffered reply that
   * fails is then never decrypted at all. */
  requireVerified?: boolean;
  signal?: AbortSignal;
  onStep?: (event: StepEvent) => void;
  onDelta?: (text: string, kind: "content" | "reasoning") => void;
}

export interface IncognitoUsage { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number }

export interface IncognitoChatResult {
  text: string;
  reasoning: string;
  finishReason: string | null;
  usage: IncognitoUsage | null;
  receiptId: string | null;
  /** null when the gateway issued no receipt; `verified: false` when it did not check out. */
  audit: ReceiptAudit | null;
  identity: IncognitoIdentity;
  /** What crossed the NATION gateway, for the "what the gateway saw" view. */
  wire: { requestBytes: number; sealedFields: number; responseBytes: number; nonce: string; clientPublicKey: string; preview: string };
}

const RECEIPT_RETRY_MS = [0, 250, 500, 1000, 1500, 2500];
const sleep = (ms: number, signal?: AbortSignal) => new Promise<void>((resolve, reject) => {
  if (!ms) return resolve();
  const timer = setTimeout(resolve, ms);
  signal?.addEventListener("abort", () => { clearTimeout(timer); reject(signal.reason); }, { once: true });
});

async function errorFrom(response: Response): Promise<IncognitoRequestError> {
  let message = `HTTP ${response.status}`;
  let type: string | undefined;
  try {
    const body = await response.json() as { error?: { message?: unknown; type?: unknown } | string };
    if (typeof body.error === "string") message = body.error;
    else if (body.error && typeof body.error.message === "string") {
      message = body.error.message;
      if (typeof body.error.type === "string") type = body.error.type;
    }
  } catch { /* keep the status line */ }
  return new IncognitoRequestError(message, response.status, type);
}

export function createIncognitoClient(options: IncognitoClientOptions) {
  const gateway = options.gatewayURL.replace(/\/+$/, "");
  const fetchImpl = options.fetch ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
  const origin = options.attestationOrigin ?? PHALA_ACI_ORIGIN;
  let identity: Promise<IncognitoIdentity> | undefined;
  let servedDigest: string | null = null;

  const establish = async (force = false): Promise<IncognitoIdentity> => {
    if (identity && !force) {
      const current = await identity.catch(() => undefined);
      if (current && identityFresh(current, servedDigest, options.now?.() ?? Date.now())) return current;
    }
    servedDigest = null;
    identity = establishIdentity({ origin, fetch: fetchImpl, policy: options.policy, verifier: options.verifier, now: options.now });
    identity.catch(() => { identity = undefined; });
    return identity;
  };

  const request = (path: string, init: RequestInit) => fetchImpl(`${gateway}${path}`, {
    ...init,
    redirect: "error",
    ...(options.credentials ? { credentials: options.credentials } : {}),
    headers: { ...options.headers, ...(init.headers as Record<string, string> | undefined) },
  });

  const fetchReceipt = async (receiptId: string, signal?: AbortSignal): Promise<Record<string, unknown> | null> => {
    for (const delay of RECEIPT_RETRY_MS) {
      await sleep(delay, signal);
      const response = await request(`/aci/receipts/${encodeURIComponent(receiptId)}`, { method: "GET", signal });
      if (response.ok) return await response.json() as Record<string, unknown>;
      if (response.status !== 404) throw await errorFrom(response);
    }
    return null;
  };

  async function chat(input: IncognitoChatInput): Promise<IncognitoChatResult> {
    const step = (name: IncognitoStep, status: StepEvent["status"], detail?: string) =>
      input.onStep?.({ step: name, status, ...(detail ? { detail } : {}) });
    let current: IncognitoStep = "attest";
    const advance = (name: IncognitoStep) => { current = name; step(name, "active"); };
    try {
      advance("attest");
      const verified = await establish();
      step("attest", "done", `Intel ${verified.teeType.toUpperCase()} · ${verified.keysetDigest.slice(0, 19)}…`);

      advance("encrypt");
      const stream = input.stream !== false;
      const exchange = await openExchange({ servicePublicKey: verified.e2eeKey.publicKey, model: input.model, now: options.now });
      const body: ChatRequestBody = {
        model: input.model,
        messages: input.messages,
        stream,
        ...(stream ? { stream_options: { include_usage: true } } : {}),
        ...(input.maxTokens ? { max_tokens: input.maxTokens } : {}),
        ...(input.temperature !== undefined ? { temperature: input.temperature } : {}),
        // Fail closed upstream too: only a verified TEE route may serve (ACI §5.3).
        provider: { aci_verified: true },
      };
      const sealed = await exchange.sealRequest(body);
      step("encrypt", "done", `${sealed.sealedFields} field${sealed.sealedFields === 1 ? "" : "s"} sealed · X25519 + AES-256-GCM`);

      advance("send");
      const response = await request("/chat/completions", {
        method: "POST",
        body: sealed.wire,
        signal: input.signal,
        headers: { "content-type": "application/json", accept: stream ? "text/event-stream" : "application/json", ...exchange.headers() },
      });
      if (!response.ok) throw await errorFrom(response);
      servedDigest = response.headers.get("x-aci-keyset-digest");
      if (response.headers.get("x-e2ee-applied") !== "true") {
        throw new IncognitoVerificationError("The response was not end-to-end encrypted; refusing to read it.");
      }
      const receiptId = response.headers.get("x-receipt-id");
      step("send", "done", `${sealed.wire.length.toLocaleString()} encrypted bytes`);

      const log = new ByteLog();
      let text = "", reasoning = "", finishReason: string | null = null;
      let usage: IncognitoUsage | null = null;
      let responseId: string | null = null;
      const take = (choices: Awaited<ReturnType<typeof exchange.openCompletion>>) => {
        const first = choices.find((choice) => choice.index === 0);
        if (!first) return;
        if (first.content) { text += first.content; input.onDelta?.(first.content, "content"); }
        if (first.reasoning) { reasoning += first.reasoning; input.onDelta?.(first.reasoning, "reasoning"); }
        if (first.finishReason) finishReason = first.finishReason;
      };
      /** The clear members: errors, the response id, token usage. */
      const note = (json: Record<string, unknown>) => {
        if (json.error) throw new IncognitoRequestError(typeof json.error === "string" ? json.error : JSON.stringify(json.error).slice(0, 300), 502);
        if (typeof json.id === "string") responseId = json.id;
        if (json.usage && typeof json.usage === "object") usage = json.usage as IncognitoUsage;
      };
      let audit: ReceiptAudit | null = null;
      const verifyReceipt = async () => {
        advance("verify");
        const key = receiptId ?? responseId;
        const receipt = key ? await fetchReceipt(key, input.signal) : null;
        audit = receipt ? await auditReceipt({
          receipt, identity: verified, model: input.model, requestBytes: utf8(sealed.restored), responseBytes: log.bytes(),
          fetch: fetchImpl, verifier: options.verifier,
        }) : null;
        if (audit?.verified) return step("verify", "done", "signed receipt · response matched");
        const why = audit ? (audit.checks.find((check) => check.status === "fail")?.detail ?? "receipt did not verify") : "no receipt was issued";
        if (input.requireVerified) throw new IncognitoVerificationError(`The reply could not be verified (${why}).`, audit?.checks ?? []);
        step("verify", "failed", why);
      };
      if (!response.body) throw new IncognitoRequestError("The gateway returned no body.", 502);
      const reader = response.body.getReader();
      const sse = stream && (response.headers.get("content-type") ?? "").includes("text/event-stream") ? new SseDataReader() : null;
      if (sse) {
        // Streaming: decrypt each sealed delta as it lands, then check the
        // receipt over the exact stream bytes once the last one has arrived.
        advance("decrypt");
        let done = false;
        const consume = async (data: string) => {
          if (data === "[DONE]") { done = true; return; }
          const json = JSON.parse(data) as Record<string, unknown>;
          note(json);
          take(await exchange.openCompletion(json, "delta"));
        };
        try {
          for (;;) {
            const chunk = await reader.read();
            if (chunk.done) break;
            log.push(chunk.value);
            for (const data of sse.push(chunk.value)) await consume(data);
          }
        } finally {
          reader.releaseLock();
        }
        for (const data of sse.finish()) await consume(data);
        if (!done && !finishReason) throw new IncognitoRequestError("The encrypted stream ended early.", 502);
        step("decrypt", "done", "decrypted on this device");
        await verifyReceipt();
      } else {
        // Buffered: hold the sealed reply, check the signed receipt against
        // its exact bytes, and only then decrypt it on this device.
        try {
          for (;;) {
            const chunk = await reader.read();
            if (chunk.done) break;
            log.push(chunk.value);
          }
        } finally {
          reader.releaseLock();
        }
        const json = JSON.parse(new TextDecoder().decode(log.bytes())) as Record<string, unknown>;
        note(json);
        await verifyReceipt();
        advance("decrypt");
        take(await exchange.openCompletion(json, "message"));
        step("decrypt", "done", "decrypted on this device");
      }
      const receiptKey = receiptId ?? responseId;
      return {
        text, reasoning, finishReason, usage, receiptId: receiptKey, audit, identity: verified,
        wire: {
          requestBytes: sealed.wire.length, sealedFields: sealed.sealedFields, responseBytes: log.length,
          nonce: exchange.nonce, clientPublicKey: exchange.clientPublicKey,
          preview: (JSON.parse(sealed.wire) as ChatRequestBody).messages.at(-1)?.content as string ?? "",
        },
      };
    } catch (error) {
      step(current, "failed", error instanceof Error ? error.message : String(error));
      if (error instanceof IncognitoVerificationError || error instanceof E2eeError) identity = undefined;
      throw error;
    }
  }

  return {
    chat,
    /** Verify (or re-verify) the confidential gateway without sending anything. */
    identity: (force = false) => establish(force),
    async models(): Promise<Array<{ id: string; name?: string; context_length?: number; pricing?: Record<string, string> }>> {
      const response = await request("/models", { method: "GET" });
      if (!response.ok) throw await errorFrom(response);
      const json = await response.json() as { data?: unknown[] };
      return (Array.isArray(json.data) ? json.data : []) as Array<{ id: string }>;
    },
  };
}

export type IncognitoClient = ReturnType<typeof createIncognitoClient>;
