---
id: core.security.stealth
title: Stealth & Obfuscation Measures
version: 1.0.0
tags:
  - security/stealth
  - security/obfuscation
description: Compile-time string obfuscation, Fat LTO, and format-fudging protocols.
---

# Stealth & Plausible Deniability

`qcrypt` is engineered to resist reverse engineering and digital forensic footprinting.

- **String Obfuscation (`obfstr`)**: All internal strings (errors, prompts, logs) are heavily encrypted at compile-time and only decrypted ephemerally in RAM, depriving static analysis tools of structural breadcrumbs.
- **Fat LTO (Link-Time Optimization)**: Monolithic inlining across all dependencies completely flattens standard Rust binary boundaries, neutralizing tools like IDA Pro/Ghidra.
- **Format-Fudging (`--nopemhead`)**: Stripping RFC 7468 PEM headers produces raw Base64 blobs that are mathematically indistinguishable from random session tokens, establishing complete plausible deniability.
