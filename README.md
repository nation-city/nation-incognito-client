<p align="center">
  <img src="assets/nation-logo.svg" alt="NATION" width="300">
</p>

<h1 align="center">NATION Incognito — client</h1>

<p align="center">The open-source part of <a href="https://thenation.city">NATION</a> Incognito that runs on <b>your</b> device.<br>
Read it, run it, and check for yourself that your prompt is encrypted before it leaves your machine.</p>

---

## In one paragraph

When you use NATION Incognito, your prompt is **encrypted on your own device** before it is sent. NATION's servers pass it along as unreadable ciphertext. It is decrypted only inside a **hardware-protected enclave** (a sealed area of a server that even the machine's operator cannot look into), where the AI model runs. Before your device encrypts anything, it **checks the enclave's hardware certificate**. After the reply comes back, it checks a **signed receipt** proving the reply answers your exact request. Then it decrypts the reply locally. This repository is that client code.

## What is encrypted, where, and how

| | |
| --- | --- |
| **What** | The text of every message you send (`messages[].content`). The model's reply text and its reasoning text. |
| **Where** | On your device: in this library, the command-line tool, or the NATION web page. That's before anything is sent. |
| **To whom** | A public key that the enclave publishes. It's tied to the enclave by an Intel TDX hardware attestation, which your device verifies first. |
| **Algorithm** | X25519 key agreement → HKDF-SHA256 → AES-256-GCM. Every message field gets its own new one-time key and nonce ([E2EE v2](https://github.com/Dstack-TEE/private-ai-gateway), the X25519 suite). |
| **Tamper protection** | Each field is locked to its position, the model, a fresh random request nonce and a timestamp. Ciphertext moved to another field, model or request fails to decrypt. |
| **Replies** | The enclave encrypts the reply to a new key that your device makes for that one request. Only your device can decrypt it. |
| **Proof** | The enclave signs a receipt containing hashes of the exact request it received and the exact reply it sent. Your device checks the signature and both hashes. |

The core is about 230 lines: [`src/e2ee.ts`](src/e2ee.ts). It uses only the standard Web Crypto API, the same one built into browsers and Node.js.

## Who can see what

| | Your prompt and reply text | Model name, sizes, timing, token counts |
| --- | --- | --- |
| Your device | **Yes** | Yes |
| NATION's servers | **No**, ciphertext only | Yes (needed for billing) |
| Network, CDN, cloud hosting | No | Sizes and timing |
| The enclave (Phala's attested gateway) and the confidential GPU that runs the model | **Yes, inside protected memory** | Yes |

### Honest limits. Please read.

- **The AI model has to read your prompt to answer it.** Your text is decrypted inside the enclave and processed on confidential GPUs. You are trusting that hardware (Intel TDX, and the GPUs' confidential-computing mode), its manufacturers' attestation, and the measured software running inside it. Your device checks all of that cryptographically, but those checks are only as strong as the hardware.
- **NATION is a relay, not the enclave.** The enclave and its attestation are operated by [Phala](https://phala.com)'s confidential AI gateway. Your device fetches the attestation straight from Phala, not through NATION, so NATION cannot swap in a different key.
- **Some information is not encrypted:**
  - which model you picked;
  - how long your messages are, and how many there are;
  - the message roles (system, user, assistant);
  - when you sent them;
  - how many tokens were used.
  
  NATION uses token counts and sizes for billing.
- **Not available in Incognito:** tool calls, images and file uploads. The protocol can't encrypt them, so they're refused rather than sent in the clear.
- **One check is not available yet.** The enclave's own key-custody check (`id-5`) is reported as "not checked", because no verifier implements it yet. Every other required check must pass, or nothing is sent.
- **Streaming has a trade-off.** In streaming mode, text is decrypted as it arrives and the receipt is checked at the end. In buffered mode, the receipt is checked before anything is decrypted. Use `requireVerified: true` (or the CLI's `--json` output, which includes `verified`) if you need a hard guarantee.
- **The web page is code NATION sends you.** If you use Incognito in the browser, you are running JavaScript served by NATION. This repository lets you audit the logic, but a browser cannot prove the page you loaded matches it. For the strongest guarantee, use this CLI or library from source.
- This code makes no claim about what happens to your data once a reply is on your screen, or about any NATION feature other than Incognito.

## Check it yourself

You need Node.js 22.18 or newer.

```bash
git clone <this repository> && cd nation-incognito-client
npm install
npm test            # encryption round-trips and tamper tests, using the spec's official test vectors
npm run typecheck
```

Verify the live enclave right now. No account is needed for this part:

```bash
node src/cli.ts doctor
```

That command fetches the enclave's hardware attestation and checks it against Intel's root of trust. It also checks the measured software and the production OS allowlist, and confirms that the encryption key belongs to that attested enclave.

## Use it

```bash
export NATION_API_KEY=your_key_here     # a NATION Incognito key, or a NATION Compute key with private mode on
export NATION_BASE_URL=https://api.thenation.city/api/v1/incognito   # for NATION Compute keys

echo "Summarise the risks in my contract draft" | node src/cli.ts request --json --max-tokens 400
```

Or as a library:

```ts
import { createIncognitoClient } from "./src/index.ts";

const client = createIncognitoClient({
  gatewayURL: "https://api.thenation.city/api/v1/incognito",
  headers: { Authorization: `Bearer ${process.env.NATION_API_KEY}` },
});
const result = await client.chat({
  model: "openai/gpt-oss-120b",
  messages: [{ role: "user", content: "Hello from my own machine" }],
  maxTokens: 300,
  requireVerified: true,
});
console.log(result.text, result.audit?.verified);
```

Get an API key at **[thenation.city](https://thenation.city)**.

## What's in this repository

| File | What it does |
| --- | --- |
| `src/e2ee.ts` | The encryption: key agreement, per-field AES-256-GCM, associated data, request sealing, reply decryption |
| `src/verify.ts` | The checks: enclave attestation before sending, and the signed receipt after the reply |
| `src/client.ts` | The full flow: verify → encrypt → send → decrypt → check the receipt |
| `src/run.ts`, `src/cli.ts` | The `nation-incognito` command-line tool |
| `src/bytes.ts`, `src/jcs.ts` | Small helpers: hex/UTF-8 conversion and JSON canonicalisation (RFC 8785) |
| `test/e2ee.test.ts` | Round-trip, wrong-key and tamper tests |

The attestation and receipt checks use the pinned [`@phala/aci-verifier`](https://www.npmjs.com/package/@phala/aci-verifier) package (Apache-2.0). It's installed as a dependency, not copied here.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). To report a security problem, see [SECURITY.md](SECURITY.md).
