---
id: app.interface.cli
title: Qcrypt Command-Line Interface Schema
version: 1.0.0
tags:
  - interface/cli
  - app/orchestration
description: Defines the structure and parameters of the qcrypt clap-based command line interface.
schema_metadata:
  type: cli_clap
  commands:
    - name: keygen
      description: Generates ML-KEM quantum-resistant keypairs.
      parameters:
        - name: pass
          type: string
          required: false
        - name: yubikey
          type: boolean
          required: false
        - name: yubikey_and_pass
          type: boolean
          required: false
        - name: stego
          type: path
          required: false
    - name: keygen-eth
      description: Generates deterministic Ethereum secp256k1 private keys for Web3 signing.
      parameters:
        - name: deterministic
          type: boolean
        - name: salt
          type: string
        - name: passphrase
          type: string
        - name: yubikey
          type: boolean
    - name: encrypt
      description: Encrypts a payload for local storage, IPFS, or Arweave.
      parameters:
        - name: arweave_eth_key
          type: string
          global: true
        - name: yubikey_ethkey_useslot2
          type: boolean
          global: true
        - name: yubikey_ethkey_salt
          type: string
          global: true
    - name: yubikey
      description: Injects deterministic HMAC-SHA1 secrets to Slot 2 of a YubiKey.
      parameters:
        - name: genhmacsha1
          type: boolean
        - name: yubikey_direct
          type: boolean
        - name: yubikey_direct_touch
          type: boolean
---

# CLI Application Interface
Detailed documentation of the CLI orchestration logic.
