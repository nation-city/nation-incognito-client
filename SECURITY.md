# Security policy

NATION takes the security of this code seriously, especially anything that could weaken the privacy of Incognito.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report it privately through GitHub: open this repository's **Security** tab, choose **Report a vulnerability**, and describe:

- what you found and where (file and line if you can);
- how to reproduce it;
- what an attacker could do with it.

We will acknowledge your report, keep you updated while we fix it, and credit you when the fix is published if you'd like.

## What is in scope

- The on-device encryption and decryption (`src/e2ee.ts`).
- The enclave attestation and receipt checks (`src/verify.ts`, `src/client.ts`).
- Anything that would let someone other than the attested enclave read a prompt, or let a forged reply pass as verified.

Problems in third-party packages (for example `@phala/aci-verifier`) are also welcome. Where it makes sense, please report them upstream as well.
