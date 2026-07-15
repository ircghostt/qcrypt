---
id: core.engine.pipeline
title: MPMC Stream Encryption Pipeline
version: 1.0.0
tags:
  - engine/parallel
  - engine/chunking
description: Details the 1MB chunked stream encryption architecture utilizing dynamic Multi-Producer Multi-Consumer threading.
---

# Parallel Cryptographic Pipeline

`qcrypt` achieves high throughput by strictly avoiding single-threaded monolithic memory buffers. 

- **Streamed Chunking**: Data is ingested via `std::io` streams in 1 Megabyte (1MB) chunks. This enforces a negligible, flat RAM footprint, completely eliminating Out-Of-Memory (OOM) attack vectors on massive payloads.
- **MPMC Parallelism**: Cryptographic operations (AES-GCM encryption/decryption) are mapped across a Multi-Producer Multi-Consumer (MPMC) channel. The engine dynamically spawns worker threads equal to the logical CPU core count.
- **Out-of-Order Resequencing**: Chunks are processed asynchronously and instantly reassembled in deterministic order using an in-memory `BTreeMap` prior to being flushed to disk.
