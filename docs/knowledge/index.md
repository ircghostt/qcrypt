---
id: root.index
title: Qcrypt Open Knowledge Format Root Index
version: 1.0.0
tags:
  - index/root
description: The entry point for the Open Knowledge Format (OKF) DAG of the Qcrypt project.
---

# Qcrypt Knowledge Base

This index establishes the high-level domain mapping for the Open Knowledge Format (OKF) integration of `qcrypt`. The documentation graph is organized deterministically into strict namespaces.

## High-Level Domains

- **`core.crypto`**: All fundamental cryptographic primitives, encryption, decryption, algorithms, and key derivation components.
  - `[[core.crypto.hybrid]]`: ML-KEM + AES-GCM Encapsulation Pipeline.
  - `[[core.crypto.yubikey]]`: Deterministic Key Generation and Hardware Provisioning.
  - `[[core.crypto.manifest]]`: BLAKE3 Cryptographic Manifest Sealing & Forensics.
  - `[[core.crypto.stego]]`: Stride-Dispersed LSB Steganography.
- **`core.security`**: Threat models, defense layers, and stealth implementation.
  - `[[core.security.memory]]`: OS Virtual Locking and Transient Sanitization.
  - `[[core.security.stealth]]`: String Obfuscation, Fat LTO, and Format-Fudging.
- **`core.engine`**: The physical state machine orchestrating data IO.
  - `[[core.engine.pipeline]]`: MPMC Chunked Stream Parallel Encryption.
- **`app.interface`**: User interfaces, command-line interfaces, and UI orchestration.
  - `[[app.interface.cli]]`: Clap Command-Line Argument Schema.
  - `[[app.interface.gui]]`: Egui-based Native Application Window.
- **`core.network`**: Web3 integration, decentralized storage, and remote APIs.
  - `[[core.network.arweave]]`: Irys/Arweave Node Integration.
  - `[[core.network.ipfs]]`: IPFS Pinata Gateway Integration.

## Bundle Traversal
To navigate this graph, follow the semantic bracket links `[[domain.subdomain.concept]]`. All concepts are isolated into independent OKF files matching their specific IDs.
