---
id: core.security.memory
title: Memory Hardening Protocols
version: 1.0.0
tags:
  - security/memory
  - security/isolation
description: Implementation details for OS-level virtual memory locking (memsec) and transient buffer sanitization (zeroize).
---

# In-Memory Defense

The `qcrypt` engine implements strict physical and virtual memory hardening techniques to thwart forensic memory dumping and side-channel extraction.

- **Virtual Locking (`memsec`)**: Critical buffers (such as the raw asymmetric private keys and symmetric shared secrets) are locked into physical RAM. The OS kernel is mathematically prevented from paging this memory out to `pagefile.sys` or `swap`, defeating cold-boot attacks.
- **Transient Sanitization (`zeroize`)**: Ephemeral buffers containing the plaintext passphrase or derived Argon2id keys are securely zeroed out immediately upon their release, preventing residual ghost data from remaining in heap memory.
