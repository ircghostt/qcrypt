---
id: core.network.arweave
title: Arweave/Irys Zero-Disk Integration
version: 1.0.0
tags:
  - network/web3
  - network/arweave
description: Zero-disk Ethereum secp256k1 signed uploads to the Irys Node 2 network for permanent Arweave storage.
---

# Arweave Network Integration

The `qcrypt` engine integrates deeply with the Arweave permaweb via Irys L2 routing, strictly executing in a zero-disk context.

- **ANS-104 Deep Hashing**: Cryptographic payloads are structurally formatted into `ANS-104` DataItems. The engine recursively hashes the payload and structural tags (owner, tags, data) using `SHA-384` to construct the Deep Hash matrix.
- **Ethereum Web3 Signature**: The final deep hash is prepended with the standard Ethereum prefix (`\x19Ethereum Signed Message:\n`) and hashed via `Keccak256`. The payload is then cryptographically signed natively in RAM utilizing a recoverable `secp256k1` ECDSA signature derived from the injected Ethereum private key.
- **Zero-Disk Streaming**: The compiled binary byte stream is pushed directly to `https://uploader.irys.xyz/tx/ethereum` without ever hitting the physical disk, maximizing forensic opsec.
- **Dynamic Fallback Retrieval**: URL resolution dynamically queries the high-speed Irys L2 gateway. On a cache miss, it autonomously falls back to the Arweave L1 native gateway.
