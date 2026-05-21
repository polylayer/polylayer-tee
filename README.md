# polylayer-tee

The signing oracle behind Polylayer's one-click trading. It runs inside
an AWS Nitro Enclave: a stateless service that derives per-user signing
keys from a master secret existing only in enclave memory, and produces
a signature only when the request matches an intent the user already
authorized.

This repository is the enclave's Rust source. Deployment infrastructure
(CDK stacks, bootstrap scripts, enclave image build) is kept separate
and is intentionally not part of this repository.

## What it does

The enclave exposes a small HTTP API that the Polylayer trading backend
calls. It signs on behalf of users across several venues:

- Polymarket CLOB orders and EVM transactions
- Hyperliquid orders and bridge permits
- Jupiter swap transactions on Solana
- Polyleverage delegated sessions, and Solana price / liquidation /
  resolution attestations

Private keys are never stored. Each user's key is derived
deterministically (HKDF for Solana delegates, BIP-44 for EVM) from a
master mnemonic. The enclave refuses to sign anything that does not
match a previously authorized user intent.

## Crate layout

| Crate     | Purpose                                                                 |
|-----------|-------------------------------------------------------------------------|
| `core`    | Key derivation and chain-specific signing (EVM, Solana, Polymarket, Hyperliquid, Jupiter) |
| `storage` | KMS, S3, and DynamoDB access over vsock; session encryption and storage |
| `nsm`     | AWS Nitro Security Module bindings (attestation documents, entropy)     |
| `server`  | The HTTP signing API and request routing                               |

## Security model

- The master secret exists only in enclave memory. It is never written
  to disk in plaintext and never leaves the enclave.
- At rest it is a KMS-sealed ciphertext. KMS decryption is conditioned
  on the enclave's attestation measurement (PCR0), so only an enclave
  running this exact code can unseal it.
- The enclave has no direct network interface. All outbound AWS calls
  (KMS, S3, DynamoDB) traverse a vsock proxy on the parent instance.
- Every signing request is checked against a user-authorized intent
  before a signature is produced.

## Build

```sh
cargo build --workspace
```

The crates target a Linux enclave environment; `nsm` is a thin binding
over the Nitro hypervisor interface.

## License

Dual-licensed under MIT or Apache-2.0.
