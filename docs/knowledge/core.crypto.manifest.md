---
id: core.crypto.manifest
title: Cryptographic Manifest Sealing
version: 1.0.0
tags:
  - crypto/integrity
  - crypto/blake3
description: Implementation of the rolling BLAKE3 hash and QCRYPTOK manifest for tamper-evident structural verification.
---

# Cryptographic Manifest Sealing

To ensure absolute end-to-end data integrity across volatile storage and decentralized swarms, `qcrypt` utilizes structural manifest sealing.

- **Rolling BLAKE3 Hash**: A continuous hash is computed against the plaintext during encryption.
- **Manifest Injection**: Upon hitting EOF, the final BLAKE3 hash, total byte count, and chunk count are encapsulated into a `QCRYPTOK` structural manifest and appended to the cipher stream.
- **Tamper-Evident Decryption**: During decryption, if the active rolling hash deviates from the enclosed `QCRYPTOK` manifest (indicating bit-flipping, file truncation, or adversarial modification), the decryption process instantly aborts.
- **OS Sync**: Explicit `sync_all()` commands force write-cache eviction to disk to prevent silent tail-end data loss.
