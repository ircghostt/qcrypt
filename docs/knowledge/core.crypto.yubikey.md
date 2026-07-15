---
id: core.crypto.yubikey
title: YubiKey Hardware Token Operations
version: 1.0.0
tags:
  - crypto/hardware-token
  - crypto/derivation
description: Deterministic key generation and direct hardware HMAC-SHA1 injection for YubiKey Slot 2.
---

# YubiKey Operations

Handles zero-disk hardware injection of symmetric secrets into YubiKey PC/SC devices, and the deterministic derivation of secp256k1 Ethereum wallets using Argon2id mathematically folded over the hardware HMAC response.
