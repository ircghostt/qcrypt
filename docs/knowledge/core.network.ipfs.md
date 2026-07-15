---
id: core.network.ipfs
title: IPFS Swarm Integration
version: 1.0.0
tags:
  - network/ipfs
  - network/pinata
description: Zero-allocation IPFS streaming via Pinata and dynamic public gateway resolution.
---

# IPFS Swarm Integration

The `qcrypt` engine integrates with the InterPlanetary File System (IPFS) to bypass centralized data silos and avoid local forensic footprinting.

- **Zero-Allocation Upstreaming**: When routing to IPFS via Pinata (`--ipfs_pinata_jwt`), the engine avoids loading the entire payload into RAM. Instead, it chains memory cursors (`header` -> `std::io::Read` -> `footer`) into a raw `multipart/form-data` stream, piping chunks linearly out the network adapter.
- **Dynamic Gateway Scraping**: For decryption/retrieval operations, the engine scrapes the live IPFS gateway registry (`https://ipfs.github.io/public-gateway-checker/gateways.json`), parses the JSON nodes, and dynamically selects a live gateway matching the user's tag.
- **Local IPFS Node Override**: Users can directly override the HTTP routing to point to local daemons (e.g., `http://127.0.0.1:8080/`), circumventing public scraping entirely.
