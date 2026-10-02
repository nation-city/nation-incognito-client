// Who decrypts an Incognito prompt, and did it answer this exact request?
//
// Identity (ACI §9.1): fetch the attestation report straight from the
// confidential gateway with our own fresh nonce, then check the Intel TDX
// quote to the vendor root, the nonce → statement → report_data binding, the
// keyset expiry, the measured compose (source provenance) and the production
// OS allowlist. Only then is the X25519 E2EE key taken from the quote-bound
// keyset. Any failed check refuses the prompt — nothing is sent.
//
// Response (ACI §9.3): the signed receipt must verify under the attested
// receipt key, commit to exactly the restored request bytes and the response
// bytes this client received, and cite a verified upstream TEE session.
//
// The checks themselves are @phala/aci-verifier's (pinned), loaded on first
// use so the browser only downloads it when someone turns Incognito on.
import type * as AciVerifier from "@phala/aci-verifier";
import { randomBytes, toHex } from "./bytes.ts";
import { X25519_SUITE } from "./e2ee.ts";

/** Phala's confidential AI gateway. The attestation report is public. */
export const PHALA_ACI_ORIGIN = "https://inference.phala.com";

export type CheckStatus = "pass" | "fail" | "skip" | "info";
export interface IncognitoCheck { id: string; section?: string; title: string; status: CheckStatus; detail?: string }

export type Verifier = Pick<typeof AciVerifier, "reportTranscript" | "receiptTranscript">;
let loaded: Promise<Verifier> | undefined;
export const loadVerifier = (): Promise<Verifier> => (loaded ??= import("@phala/aci-verifier"));

export class IncognitoVerificationError extends Error {
  readonly checks: IncognitoCheck[];
  constructor(message: string, checks: IncognitoCheck[] = []) {
    super(message);
    this.checks = checks;
  }
}

export interface IncognitoKeyset {
  not_after: number;
  receipt_signing_keys: Array<{ key_id: string; algo: string; public_key: string }>;
  e2ee_public_keys: Array<{ key_id: string; algo: string; public_key: string }>;
  [key: string]: unknown;
}

export interface IncognitoIdentity {
  origin: string;
  keysetDigest: string;
  keyset: IncognitoKeyset;
  /** The quote-bound X25519 key every request field is sealed to. */
  e2eeKey: { keyId: string; publicKey: string };
  notAfter: number;
  serving: string;
  teeType: string;
  composeHash?: string;
  provenance?: { repoUrl: string | null; repoCommit: string | null };
  checks: IncognitoCheck[];
  verifiedAt: number;
}

export interface IdentityPolicy {
  /** Reviewed sha256(app_compose) values; empty accepts any measured compose. */
  acceptedComposeHashes?: readonly string[];
}

/** Checks that must pass before a prompt may leave. id-5 (KMS custody) is not
 * implemented by any ACI verifier yet and is reported as a skip. */
const REQUIRED_IDENTITY = ["id-1", "id-2", "id-3", "id-4", "policy-os", "id-6"];

export async function establishIdentity(input: {
  origin?: string;
  fetch?: typeof fetch;
  policy?: IdentityPolicy;
  verifier?: Verifier;
  now?: () => number;
} = {}): Promise<IncognitoIdentity> {
  const origin = (input.origin ?? PHALA_ACI_ORIGIN).replace(/\/+$/, "");
  const fetchImpl = input.fetch ?? fetch;
  const nonce = toHex(randomBytes(32));
  let report: AciVerifier.AttestationReport;
  try {
    const response = await fetchImpl(`${origin}/v1/aci/attestation?nonce=${nonce}`, { redirect: "error", credentials: "omit" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    report = await response.json() as AciVerifier.AttestationReport;
  } catch (error) {
    throw new IncognitoVerificationError(`Could not fetch the enclave's attestation report: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (report?.api_version !== "aci/1") throw new IncognitoVerificationError("The attestation report is not ACI aci/1.");
  if (!report.service_capabilities?.supported_e2ee_versions?.includes("2")) {
    throw new IncognitoVerificationError("The confidential gateway does not terminate E2EE v2.");
  }
  const verifier = input.verifier ?? await loadVerifier();
  const transcript = await verifier.reportTranscript(report, nonce, {
    online: true,
    requireProductionOs: true,
    ...(input.policy?.acceptedComposeHashes?.length ? { acceptedComposeHashes: input.policy.acceptedComposeHashes } : {}),
    ...(input.now ? { now: Math.floor(input.now() / 1000) } : {}),
  });
  const keyset = transcript.verification.keyset as IncognitoKeyset | undefined;
  const digest = transcript.verification.workloadKeysetDigest;
  const key = keyset?.e2ee_public_keys.find((entry) => entry.algo === X25519_SUITE);
  // §9.1(6): the channel is bound when the E2EE key used is in the quote-bound
  // keyset. Every field is sealed to this key, so that is the binding — a TLS
  // pin to the gateway is not needed (and a browser cannot observe one).
  const checks: IncognitoCheck[] = transcript.lines.map((line) => line.id !== "id-6" ? line : {
    ...line,
    status: key ? "pass" : "fail",
    detail: key ? `every field is sealed to E2EE v2 key "${key.key_id}" from the quote-bound keyset (§9.1(6))` : "the attested keyset lists no X25519 E2EE v2 key",
  });
  const failed = checks.filter((check) => check.status === "fail" || (REQUIRED_IDENTITY.includes(check.id) && check.status !== "pass"));
  const missing = REQUIRED_IDENTITY.filter((id) => !checks.some((check) => check.id === id));
  if (failed.length || missing.length || !keyset || !digest || !key) {
    const reason = failed[0]?.detail ?? (missing.length ? `missing check ${missing.join(", ")}` : "no usable keyset");
    throw new IncognitoVerificationError(`The confidential gateway did not verify: ${reason}`, checks);
  }
  const provenance = report.attestation.source_provenance;
  return {
    origin,
    keysetDigest: digest,
    keyset,
    e2eeKey: { keyId: key.key_id, publicKey: key.public_key },
    notAfter: keyset.not_after,
    serving: typeof report.service_capabilities?.serving === "string" ? report.service_capabilities.serving : "aggregator",
    teeType: report.attestation.tee_type,
    ...(transcript.composeHash ? { composeHash: transcript.composeHash } : {}),
    ...(provenance ? { provenance: { repoUrl: provenance.repo_url ?? null, repoCommit: provenance.repo_commit ?? null } } : {}),
    checks,
    verifiedAt: input.now?.() ?? Date.now(),
  };
}

/** An identity stays usable until its keyset expires or the gateway reports a
 * different keyset digest (ACI §5.2), whichever comes first. */
export function identityFresh(identity: IncognitoIdentity, servedDigest: string | null, now = Date.now()): boolean {
  return now / 1000 < identity.notAfter - 60 && (!servedDigest || servedDigest === identity.keysetDigest);
}

export interface ReceiptAudit {
  verified: boolean;
  receiptId: string;
  servedAt?: number;
  sessionId?: string;
  upstreamModel?: string;
  checks: IncognitoCheck[];
  receipt: Record<string, unknown>;
}

const REQUIRED_RECEIPT = ["receipt-1", "receipt-2", "receipt-3", "receipt-4", "upstream-1", "upstream-2"];

/** §9.3 over a fetched receipt: signature, keyset, both body hashes, and the
 * cited upstream TEE session (fetched from the gateway's public endpoint). */
export async function auditReceipt(input: {
  receipt: Record<string, unknown>;
  identity: IncognitoIdentity;
  model: string;
  requestBytes: Uint8Array;
  responseBytes: Uint8Array;
  fetch?: typeof fetch;
  verifier?: Verifier;
}): Promise<ReceiptAudit> {
  const { receipt, identity } = input;
  const events = Array.isArray(receipt.event_log) ? receipt.event_log as Array<Record<string, unknown>> : [];
  const upstream = events.find((event) => event?.type === "upstream.verified");
  const sessionId = typeof upstream?.session_id === "string" && /^[0-9a-f]{64}$/.test(upstream.session_id) ? upstream.session_id : undefined;
  let session: unknown;
  if (sessionId) {
    try {
      const response = await (input.fetch ?? fetch)(`${identity.origin}/v1/aci/sessions/${sessionId}`, { redirect: "error", credentials: "omit" });
      if (response.ok) session = await response.json();
    } catch { /* reported by upstream-2 as unverifiable */ }
  }
  const verifier = input.verifier ?? await loadVerifier();
  const transcript = await verifier.receiptTranscript(
    receipt as AciVerifier.ReceiptEnvelope,
    identity.keyset as AciVerifier.WorkloadKeyset,
    identity.keysetDigest,
    input.requestBytes,
    input.responseBytes,
    { ...(session ? { session } : {}), requiresVerified: true, serving: identity.serving },
  );
  const checks: IncognitoCheck[] = [...transcript.lines];
  const same = (id: string, title: string, ok: boolean, detail: string) =>
    checks.push({ id, title, status: ok ? "pass" : "fail", ...(ok ? {} : { detail }) });
  same("receipt-model", "receipt names the model this request asked for", receipt.model === input.model, `receipt model ${JSON.stringify(receipt.model)} ≠ ${JSON.stringify(input.model)}`);
  same("receipt-endpoint", "receipt is for POST /v1/chat/completions", receipt.endpoint === "/v1/chat/completions" && receipt.method === "POST", `receipt endpoint ${String(receipt.method)} ${String(receipt.endpoint)}`);
  const verified = checks.every((check) => check.status !== "fail")
    && REQUIRED_RECEIPT.every((id) => identity.serving === "direct" && id === "upstream-2" ? true : checks.some((check) => check.id === id && check.status === "pass"));
  return {
    verified,
    receiptId: String(receipt.receipt_id ?? ""),
    ...(typeof receipt.served_at === "number" ? { servedAt: receipt.served_at } : {}),
    ...(sessionId ? { sessionId } : {}),
    ...(typeof upstream?.model_id === "string" ? { upstreamModel: upstream.model_id } : {}),
    checks,
    receipt,
  };
}
