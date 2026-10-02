// nation-incognito — private prompts for terminal agents.
//
//   nation-incognito doctor [--json]
//   nation-incognito models [--json]
//   nation-incognito request [--input FILE] [--model ID] [--max-tokens N] [--json] [--receipt FILE] [--stream]
//   nation-incognito instructions
//
// Verify the enclave → seal the prompt → send through NATION → check the
// signed receipt → decrypt. Exit 0 on success, 2 for input or configuration
// problems, 1 for connection, verification or output failures.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { createIncognitoClient, IncognitoRequestError, type IncognitoChatResult } from "./client.ts";
import { x25519Supported } from "./e2ee.ts";
import { IncognitoVerificationError, PHALA_ACI_ORIGIN, type IncognitoCheck } from "./verify.ts";

const VERSION = "0.1.0";
const DEFAULT_BASE_URL = "https://thenation.city/swarm/api/incognito/v1";
const COMPUTE_BASE_URL = "https://api.thenation.city/api/v1/incognito";
const KEY_HINT = "an Incognito key (NATION → Incognito → Keys) or a NATION Compute key with private mode on";
const MAX_PROMPT_BYTES = 2 * 1024 * 1024;

class UsageError extends Error {}

const HELP = `nation-incognito ${VERSION} — end-to-end encrypted inference for terminal agents

Usage:
  nation-incognito doctor [--json]            verify the enclave and your NATION connection
  nation-incognito models [--json]            list attested (TEE) models and prices
  nation-incognito request [options]          send one private prompt (stdin or --input)
  nation-incognito instructions               how a coding agent should use this tool

Request options:
  --input FILE        read the prompt from FILE instead of stdin
  --model ID          attested model id (default: the server's default)
  --max-tokens N      output budget (default 1024)
  --json              print { text, reasoning, model, receiptId, verified, checks, usage }
  --receipt FILE      save the public evidence (receipt, enclave checks) to a new FILE
  --stream            print text as it arrives; the receipt is checked at the end

Environment:
  NATION_API_KEY                      an Incognito key from NATION → Incognito → Keys, or a
                                      NATION Compute key (sk-nation-…) with private mode on (required)
  NATION_BASE_URL                     default ${DEFAULT_BASE_URL}
                                      NATION Compute: ${COMPUTE_BASE_URL}
  NATION_INCOGNITO_MODEL              default model id
  NATION_INCOGNITO_COMPOSE_HASHES     comma-separated reviewed release hashes to require
  NATION_INCOGNITO_ATTESTATION_ORIGIN default ${PHALA_ACI_ORIGIN}
`;

const INSTRUCTIONS = `# Using nation-incognito from a coding agent

nation-incognito sends one prompt to an AI model running inside attested
confidential hardware. The prompt is encrypted on this machine before it
leaves; NATION's gateway only relays ciphertext; the reply is checked
against a signed receipt and decrypted locally.

Rules for agents:
1. Read the key from NATION_API_KEY. Never ask for it in conversation and
   never put it in command arguments, files, or logs.
2. Pass prompt text through stdin or --input FILE, never as an argument
   (arguments are visible to other processes).
3. Run \`nation-incognito doctor --json\` once per session before the first request.
4. Run \`nation-incognito request --json < prompt.txt\` and parse stdout only
   when the exit code is 0. Show the user \`text\` and \`receiptId\`.
5. On a non-zero exit, report the message from stderr. Do not retry the same
   prompt through a normal (non-private) model, do not switch providers, and do
   not repeat a request that may already have been billed.

What this protects: the prompt and reply contents between this machine and
the enclave. It does not hide anything from this machine itself — the shell,
the agent, and anything else here can still see the text you pass in.
Visible to NATION: model, sizes, timing, token counts.
`;

function config() {
  const apiKey = process.env.NATION_API_KEY?.trim();
  const baseURL = (process.env.NATION_BASE_URL?.trim() || DEFAULT_BASE_URL).replace(/\/+$/, "");
  const url = new URL(baseURL);
  if (url.protocol !== "https:" && !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) {
    throw new UsageError("NATION_BASE_URL must be https (plain http is allowed only for localhost).");
  }
  const composeHashes = (process.env.NATION_INCOGNITO_COMPOSE_HASHES ?? "").split(",").map((hash) => hash.trim().toLowerCase()).filter(Boolean);
  if (composeHashes.some((hash) => !/^[0-9a-f]{64}$/.test(hash))) throw new UsageError("NATION_INCOGNITO_COMPOSE_HASHES must be 64-hex values separated by commas.");
  return {
    apiKey,
    baseURL,
    attestationOrigin: process.env.NATION_INCOGNITO_ATTESTATION_ORIGIN?.trim() || PHALA_ACI_ORIGIN,
    composeHashes,
    model: process.env.NATION_INCOGNITO_MODEL?.trim() || undefined,
  };
}

function clientFor(settings: ReturnType<typeof config>) {
  if (!settings.apiKey) throw new UsageError(`Set NATION_API_KEY to ${KEY_HINT}.`);
  return createIncognitoClient({
    gatewayURL: settings.baseURL,
    attestationOrigin: settings.attestationOrigin,
    headers: { authorization: `Bearer ${settings.apiKey}`, "user-agent": `nation-incognito/${VERSION}` },
    policy: { acceptedComposeHashes: settings.composeHashes },
  });
}

async function gatewayStatus(settings: ReturnType<typeof config>): Promise<{ available: boolean; enabled: boolean; defaultModel: string | null; billing: string }> {
  const response = await fetch(`${settings.baseURL.replace(/\/v1$/, "")}/status`, {
    headers: { authorization: `Bearer ${settings.apiKey}` }, redirect: "error", signal: AbortSignal.timeout(20_000),
  });
  if (response.status === 401) throw new IncognitoRequestError("NATION did not accept NATION_API_KEY (expired or revoked?).", 401);
  if (!response.ok) throw new IncognitoRequestError(`NATION returned HTTP ${response.status}`, response.status);
  return await response.json() as { available: boolean; enabled: boolean; defaultModel: string | null; billing: string };
}

const mark = (status: IncognitoCheck["status"]) => status === "pass" ? "✓" : status === "fail" ? "✗" : "–";

async function readPrompt(input: string | undefined): Promise<string> {
  let bytes: Buffer;
  if (input) {
    if (!existsSync(input)) throw new UsageError(`No such file: ${input}`);
    bytes = readFileSync(input);
  } else {
    if (process.stdin.isTTY) throw new UsageError("Pipe the prompt on stdin or pass --input FILE.");
    const parts: Buffer[] = [];
    for await (const chunk of process.stdin) parts.push(chunk as Buffer);
    bytes = Buffer.concat(parts);
  }
  if (bytes.length > MAX_PROMPT_BYTES) throw new UsageError(`The prompt is larger than ${MAX_PROMPT_BYTES} bytes.`);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes).trim();
  if (!text) throw new UsageError("The prompt is empty.");
  return text;
}

function writeEvidence(path: string, result: IncognitoChatResult) {
  if (existsSync(path)) throw new UsageError(`Refusing to overwrite ${path}.`);
  // Public evidence only: no prompt, no reply, no key.
  const evidence = {
    tool: `nation-incognito/${VERSION}`,
    receiptId: result.receiptId,
    verified: result.audit?.verified ?? false,
    receipt: result.audit?.receipt ?? null,
    receiptChecks: result.audit?.checks ?? [],
    enclave: {
      origin: result.identity.origin,
      keysetDigest: result.identity.keysetDigest,
      keyset: result.identity.keyset,
      composeHash: result.identity.composeHash ?? null,
      provenance: result.identity.provenance ?? null,
      checks: result.identity.checks,
      verifiedAt: new Date(result.identity.verifiedAt).toISOString(),
    },
    wire: { requestBytes: result.wire.requestBytes, responseBytes: result.wire.responseBytes, sealedFields: result.wire.sealedFields },
  };
  writeFileSync(path, JSON.stringify(evidence, null, 2) + "\n", { mode: 0o600, flag: "wx" });
}

async function doctor(json: boolean) {
  const settings = config();
  const report: Record<string, unknown> = { version: VERSION, baseURL: settings.baseURL, attestationOrigin: settings.attestationOrigin, apiKey: settings.apiKey ? "set" : "missing" };
  const lines: string[] = [];
  const crypto = await x25519Supported();
  report.x25519 = crypto;
  lines.push(`${crypto ? "✓" : "✗"} X25519 in Web Crypto (Node ${process.versions.node})`);
  let ok = crypto;
  try {
    const client = createIncognitoClient({ gatewayURL: settings.baseURL, attestationOrigin: settings.attestationOrigin, policy: { acceptedComposeHashes: settings.composeHashes } });
    const identity = await client.identity(true);
    report.enclave = { verified: true, keysetDigest: identity.keysetDigest, e2eeKey: identity.e2eeKey, composeHash: identity.composeHash ?? null, notAfter: identity.notAfter, checks: identity.checks };
    lines.push(`✓ Enclave verified (Intel ${identity.teeType.toUpperCase()}) · keyset ${identity.keysetDigest.slice(0, 23)}…`);
    for (const check of identity.checks) lines.push(`    ${mark(check.status)} ${check.title}`);
  } catch (error) {
    ok = false;
    const checks = error instanceof IncognitoVerificationError ? error.checks : [];
    report.enclave = { verified: false, error: error instanceof Error ? error.message : String(error), checks };
    lines.push(`✗ Enclave did not verify: ${error instanceof Error ? error.message : String(error)}`);
    for (const check of checks) lines.push(`    ${mark(check.status)} ${check.title}${check.detail && check.status === "fail" ? ` — ${check.detail}` : ""}`);
  }
  if (!settings.apiKey) {
    ok = false;
    lines.push(`✗ NATION_API_KEY is not set: use ${KEY_HINT}`);
  } else {
    try {
      const status = await gatewayStatus(settings);
      report.gateway = status;
      if (!status.available) { ok = false; lines.push("✗ Incognito is not available on this NATION server"); }
      else if (!status.enabled) {
        ok = false;
        lines.push(`✗ Private mode is off for this account — turn it on in ${status.billing === "compute" ? "your NATION Compute console" : "NATION → Incognito"}`);
      }
      else lines.push(`✓ NATION gateway ready · default model ${status.defaultModel ?? "?"} · billing: ${status.billing}`);
    } catch (error) {
      ok = false;
      report.gateway = { error: error instanceof Error ? error.message : String(error) };
      lines.push(`✗ NATION gateway: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  report.ok = ok;
  process.stdout.write(json ? JSON.stringify(report, null, 2) + "\n" : lines.join("\n") + "\n");
  return ok ? 0 : 1;
}

async function models(json: boolean) {
  const settings = config();
  const list = await clientFor(settings).models();
  if (json) { process.stdout.write(JSON.stringify(list, null, 2) + "\n"); return 0; }
  const price = (value: unknown) => typeof value === "number" ? `$${(value * 1e6).toFixed(2)}` : "?";
  for (const model of list as Array<{ id: string; name?: string; pricing?: { prompt?: number; completion?: number } }>) {
    process.stdout.write(`${model.id.padEnd(40)} ${price(model.pricing?.prompt)} in · ${price(model.pricing?.completion)} out / 1M  ${model.name ?? ""}\n`);
  }
  return 0;
}

async function request(values: { input?: string; model?: string; "max-tokens"?: string; json?: boolean; receipt?: string; stream?: boolean }) {
  const settings = config();
  const client = clientFor(settings);
  const maxTokens = values["max-tokens"] ? Number(values["max-tokens"]) : 1024;
  if (!Number.isSafeInteger(maxTokens) || maxTokens < 1 || maxTokens > 200_000) throw new UsageError("--max-tokens must be a whole number between 1 and 200000.");
  if (values.receipt && existsSync(values.receipt)) throw new UsageError(`Refusing to overwrite ${values.receipt}.`);
  const prompt = await readPrompt(values.input);
  const model = values.model ?? settings.model ?? (await gatewayStatus(settings)).defaultModel;
  if (!model) throw new UsageError("No model: pass --model (see `nation-incognito models`).");
  const progress = (line: string) => { if (!values.json && process.stderr.isTTY) process.stderr.write(line); };
  const result = await client.chat({
    model,
    messages: [{ role: "user", content: prompt }],
    maxTokens,
    stream: values.stream === true,
    // A buffered reply that fails its receipt is never decrypted.
    requireVerified: true,
    signal: AbortSignal.timeout(10 * 60_000),
    onStep: (event) => { if (event.status === "done" && event.step !== "attest") progress(`✓ ${event.step[0]!.toUpperCase()}${event.step.slice(1)} `); },
    onDelta: (text, kind) => { if (values.stream && !values.json && kind === "content") process.stdout.write(text); },
  });
  progress("\n");
  if (values.receipt) writeEvidence(values.receipt, result);
  if (values.json) {
    process.stdout.write(JSON.stringify({
      text: result.text, reasoning: result.reasoning || undefined, model, receiptId: result.receiptId,
      verified: result.audit?.verified ?? false, checks: result.audit?.checks ?? [], usage: result.usage,
    }, null, 2) + "\n");
  } else if (!values.stream) {
    process.stdout.write(result.text.endsWith("\n") ? result.text : result.text + "\n");
  } else {
    process.stdout.write("\n");
  }
  return 0;
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  const [command, ...rest] = argv;
  try {
    if (!command || command === "--help" || command === "-h" || command === "help") { process.stdout.write(HELP); return command ? 0 : 2; }
    if (command === "--version" || command === "-v") { process.stdout.write(`${VERSION}\n`); return 0; }
    if (command === "instructions") { process.stdout.write(INSTRUCTIONS); return 0; }
    const { values } = parseArgs({
      args: rest,
      strict: true,
      options: {
        json: { type: "boolean" }, input: { type: "string" }, model: { type: "string" },
        "max-tokens": { type: "string" }, receipt: { type: "string" }, stream: { type: "boolean" },
      },
    });
    if (command === "doctor") return await doctor(values.json === true);
    if (command === "models") return await models(values.json === true);
    if (command === "request") return await request(values);
    throw new UsageError(`Unknown command "${command}". Run nation-incognito --help.`);
  } catch (error) {
    const usage = error instanceof UsageError || (error instanceof TypeError && "code" in error && String((error as { code?: unknown }).code).startsWith("ERR_PARSE_ARGS"));
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`nation-incognito: ${message}\n`);
    if (error instanceof IncognitoVerificationError) {
      for (const check of error.checks.filter((entry) => entry.status === "fail")) process.stderr.write(`  ✗ ${check.title}${check.detail ? ` — ${check.detail}` : ""}\n`);
    }
    return usage ? 2 : 1;
  }
}
