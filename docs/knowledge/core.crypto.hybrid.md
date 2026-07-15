---
id: core.crypto.hybrid
title: ML-KEM Hybrid Cryptography Pipeline
version: 1.0.0
tags:
  - crypto/quantum-resistant
  - crypto/aes-gcm
description: Post-quantum asymmetric encapsulation pipeline utilizing ML-KEM1024 and AES-256-GCM.
---

# Hybrid Cryptography

This core engine handles the generation of true RNG quantum-resistant keys using the ML-KEM standard, wrapped symmetrically via AES-256-GCM derived from Passphrase/Hardware entropy.
