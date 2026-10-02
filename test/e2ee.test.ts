// Round-trip and tamper tests for the on-device encryption (E2EE v2, X25519 suite).
// Run with: npm test   (Node 22.18+ runs these TypeScript files directly)
import { test } from "node:test";
import assert from "node:assert/strict";
import { fromHex, fromUtf8, toHex, utf8 } from "../src/bytes.ts";
import { jcs } from "../src/jcs.ts";
import { MIN_SEALED_HEX, normalizeContent, openExchange, openField, requestAad, responseAad, sealField, SseDataReader, X25519_SUITE } from "../src/e2ee.ts";

// Test vectors from the public E2EE v2 specification (spec/e2ee-v2-test-vectors.md).
const VECTOR = { model: "demo-model", nonce: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", timestamp: 1750000000 };
const SPEC_SERVICE_PUBLIC = "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22";

/** The test stands in for the enclave: it holds the private key the device encrypts to. */
async function privateKeyFromSeed(seedByte: number): Promise<CryptoKey> {
  const pkcs8 = fromHex("302e020100300506032b656e04220420" + toHex(new Uint8Array(32).fill(seedByte)));
  return crypto.subtle.importKey("pkcs8", pkcs8.slice().buffer as ArrayBuffer, { name: "X25519" }, true, ["deriveBits"]);
}
async function freshKeyPair(): Promise<{ privateKey: CryptoKey; publicHex: string }> {
  const pair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
  return { privateKey: pair.privateKey, publicHex: toHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))) };
}

test("the associated data matches the specification byte for byte", () => {
  assert.equal(fromUtf8(requestAad(VECTOR, "messages.0.content")),
    `{"algo":"${X25519_SUITE}","field":"messages.0.content","model":"demo-model","nonce":"${VECTOR.nonce}","purpose":"aci.e2ee.request.v2","ts":1750000000}`);
  assert.equal(fromUtf8(responseAad(VECTOR, "chatcmpl-123", "choices.0.message.content")),
    `{"algo":"${X25519_SUITE}","field":"choices.0.message.content","id":"chatcmpl-123","model":"demo-model","nonce":"${VECTOR.nonce}","purpose":"aci.e2ee.response.v2","ts":1750000000}`);
});

test("the spec's service key is derived from its seed", async () => {
  const jwk = await crypto.subtle.exportKey("jwk", await privateKeyFromSeed(0x03));
  const x = Uint8Array.from(atob(jwk.x!.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  assert.equal(toHex(x), SPEC_SERVICE_PUBLIC);
});

test("a prompt encrypted on the device decrypts with the enclave key (round trip)", async () => {
  const enclave = await privateKeyFromSeed(0x03);
  const aad = requestAad(VECTOR, "messages.0.content");
  for (const prompt of ["hello enclave", "", "ünïcödé ✓ 日本語 🚀", "x".repeat(50_000)]) {
    const sealed = await sealField(utf8(prompt), SPEC_SERVICE_PUBLIC, aad);
    assert.match(sealed, /^[0-9a-f]+$/);
    assert.equal(sealed.length, MIN_SEALED_HEX + utf8(prompt).length * 2, "ciphertext = key + nonce + text + tag");
    if (prompt.length > 3) assert.ok(!sealed.includes(toHex(utf8(prompt)).slice(0, 16)), "no plaintext in the output");
    assert.equal(fromUtf8(await openField(sealed, enclave, aad)), prompt);
  }
});

test("the wrong key, a different field, model or request cannot decrypt it", async () => {
  const enclave = await privateKeyFromSeed(0x03);
  const stranger = await privateKeyFromSeed(0x07);
  const aad = requestAad(VECTOR, "messages.0.content");
  const sealed = await sealField(utf8("secret plan"), SPEC_SERVICE_PUBLIC, aad);
  await assert.rejects(openField(sealed, stranger, aad), /authentication/);
  await assert.rejects(openField(sealed, enclave, requestAad(VECTOR, "messages.1.content")), /authentication/);
  await assert.rejects(openField(sealed, enclave, requestAad({ ...VECTOR, model: "other" }, "messages.0.content")), /authentication/);
  await assert.rejects(openField(sealed, enclave, requestAad({ ...VECTOR, timestamp: 1 }, "messages.0.content")), /authentication/);
  // Flipping one bit of the ciphertext breaks the authentication tag.
  const last = sealed.length - 1, flipped = sealed.slice(0, last) + (sealed[last] === "0" ? "1" : "0");
  await assert.rejects(openField(flipped, enclave, aad), /authentication/);
  await assert.rejects(openField("00".repeat(10), enclave, aad), /not E2EE v2 ciphertext/);
});

test("every field gets a fresh one-time key and nonce", async () => {
  const aad = utf8(jcs({ a: 1 }));
  const one = await sealField(utf8("same text"), SPEC_SERVICE_PUBLIC, aad);
  const two = await sealField(utf8("same text"), SPEC_SERVICE_PUBLIC, aad);
  assert.notEqual(one.slice(0, 64), two.slice(0, 64), "ephemeral public keys differ");
  assert.notEqual(one.slice(64, 88), two.slice(64, 88), "AES-GCM nonces differ");
  assert.notEqual(one, two);
});

test("a whole chat request is sealed: no message text is left readable", async () => {
  const enclave = await freshKeyPair();
  const exchange = await openExchange({ servicePublicKey: enclave.publicHex, model: "demo-model" });
  const { wire, restored, sealedFields } = await exchange.sealRequest({
    model: "demo-model",
    messages: [{ role: "system", content: "Be brief." }, { role: "user", content: "My bank PIN is 4321" }],
    stream: false,
  });
  assert.equal(sealedFields, 2);
  assert.ok(!wire.includes("Be brief") && !wire.includes("4321"), "the wire body carries no message text");
  const body = JSON.parse(wire);
  // What stays visible to the relay: the model, the roles, the structure.
  assert.equal(body.model, "demo-model");
  assert.deepEqual(body.messages.map((m: { role: string }) => m.role), ["system", "user"]);
  // The enclave can open each field with the request's nonce and timestamp.
  const ctx = { model: "demo-model", nonce: exchange.nonce, timestamp: exchange.timestamp };
  assert.equal(fromUtf8(await openField(body.messages[1].content, enclave.privateKey, requestAad(ctx, "messages.1.content"))), "My bank PIN is 4321");
  assert.equal(JSON.parse(restored).messages[1].content, "My bank PIN is 4321");
  const headers = exchange.headers();
  assert.equal(headers["X-E2EE-Version"], "2");
  assert.equal(headers["X-Model-Pub-Key"], enclave.publicHex);
  assert.match(headers["X-Client-Pub-Key"], /^[0-9a-f]{64}$/);
  assert.match(headers["X-E2EE-Nonce"], /^[0-9a-f]{64}$/);
});

test("a reply sealed to this device's one-time key decrypts here (round trip)", async () => {
  const enclave = await freshKeyPair();
  const exchange = await openExchange({ servicePublicKey: enclave.publicHex, model: "demo-model" });
  const ctx = { model: "demo-model", nonce: exchange.nonce, timestamp: exchange.timestamp };
  // The enclave seals its answer to the client key the device sent in X-Client-Pub-Key.
  const content = await sealField(utf8("Here is the answer."), exchange.clientPublicKey, responseAad(ctx, "chatcmpl-1", "choices.0.message.content"));
  const [choice] = await exchange.openCompletion({ id: "chatcmpl-1", choices: [{ index: 0, message: { role: "assistant", content }, finish_reason: "stop" }] }, "message");
  assert.equal(choice.content, "Here is the answer.");
  assert.equal(choice.finishReason, "stop");
  // A reply bound to a different response id is refused.
  await assert.rejects(exchange.openCompletion({ id: "chatcmpl-2", choices: [{ index: 0, message: { content } }] }, "message"), /authentication/);
});

test("streamed replies decrypt chunk by chunk", async () => {
  const enclave = await freshKeyPair();
  const exchange = await openExchange({ servicePublicKey: enclave.publicHex, model: "demo-model" });
  const ctx = { model: "demo-model", nonce: exchange.nonce, timestamp: exchange.timestamp };
  let text = "";
  for (const piece of ["Hel", "lo ", "world"]) {
    const sealed = await sealField(utf8(piece), exchange.clientPublicKey, responseAad(ctx, "chatcmpl-9", "choices.0.delta.content"));
    const [choice] = await exchange.openCompletion({ id: "chatcmpl-9", choices: [{ index: 0, delta: { content: sealed } }] }, "delta");
    text += choice.content;
  }
  assert.equal(text, "Hello world");
});

test("helpers: content normalisation and the SSE reader", () => {
  assert.equal(normalizeContent("hi"), "hi");
  assert.deepEqual(normalizeContent("[]"), [{ type: "text", text: "[]" }]);
  const reader = new SseDataReader();
  const bytes = utf8("data: {\"a\":1}\r\n\r\ndata: [DO");
  assert.deepEqual(reader.push(bytes.subarray(0, 7)), []);
  assert.deepEqual(reader.push(bytes.subarray(7)), ["{\"a\":1}"]);
  assert.deepEqual(reader.push(utf8("NE]\n")), ["[DONE]"]);
});
