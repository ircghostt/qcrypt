# qcrypt: Post-Quantum Hybrid Cryptography Toolkit (Military-Grade)

## Overview
`qcrypt` is a standalone, enterprise-grade CLI utility designed to secure highly sensitive data against both modern classical brute-force attacks and future "Harvest Now, Decrypt Later" quantum computer threats. It implements a strict, mathematically verified hybrid-cryptographic architecture, adhering strictly to NIST and IETF guidelines.

## System Architecture

The tool utilizes a strict Hybrid Cryptography model:
1. **Asymmetric (Public-Key) Layer**: NIST FIPS 203 ML-KEM-1024 (Module-Lattice-Based Key Encapsulation Mechanism). Provides post-quantum key exchange.
2. **Symmetric (Payload) Layer**: AES-256-GCM (Advanced Encryption Standard in Galois/Counter Mode). Provides high-speed, authenticated payload encryption.

> [!CAUTION]
> **1:1 Key Binding**: `qcrypt` generates asymmetric keys specifically engineered for this hybrid pipeline. External standard RSA/ECC keys cannot be imported, and these ML-KEM keys cannot be used outside of this architecture.

## Enterprise & Military-Grade Defenses

The architecture has been heavily fortified against physical, memory, and cryptographic threat vectors:

### 1. Cryptographic Standards Compliance
- **RFC 7468 (PEM Base64 Armoring)**: Asymmetric keys are strictly Base64 encoded and wrapped in standard ASCII headers (e.g., `-----BEGIN ENCRYPTED ML-KEM-1024 PRIVATE KEY-----`).
- **NIST SP 800-56C (HKDF-SHA256)**: The raw ML-KEM shared secret is mathematically expanded and cryptographically separated via HKDF using a strict domain separator (`qcrypt-aes-gcm`) before touching the symmetric cipher.
- **AEAD Integrity Binding (AAD)**: Structural headers (KEM Ciphertext and Nonce) are explicitly bound to the AES-GCM engine as Additional Authenticated Data (AAD). Malicious bit-flipping in the archive headers triggers an immediate, mathematically proven MAC verification failure during decryption.

### 2. At-Rest Defense (Physical Theft)
- **Argon2id Key Wrapping**: The `priv_key.pem` is encrypted at rest using AES-256-GCM. The AES key is derived from a user passphrase using Argon2id (the OWASP/NIST recommended memory-hard PBKDF), utilizing a random 16-byte salt.
- **16-Character Minimum Enforcement**: The program strictly rejects passphrases shorter than 16 characters to mathematically defeat dictionary and cloud-GPU brute-force attacks.

### 3. Hardware-Bound Authentication (YubiKey Tri-Mode)
- **Zero-Trust Hardware Binding**: `qcrypt` features direct integration with Yubico HMAC-SHA1 Challenge-Response protocols (Slot 2). 
- **Tri-Mode Support**: The cryptographic entropy can be derived strictly from a Passphrase, strictly from a Physical YubiKey Token, or via a highly secure Hybrid Mode (Hardware Token + Passphrase).
- **Physical Proof of Presence**: Operations utilizing hardware tokens mandate a physical capacitive touch to the YubiKey, preventing remote automated extraction or malware side-channeling.

### 4. In-Memory Defense (Forensics & Compromise)
- **OS-Level Virtual Memory Locking (`memsec`)**: Critical buffers (Private Key bytes, Shared Secrets, AES Keys) are structurally isolated via `VirtualLock` (Windows) or `mlock` (Unix). The OS kernel is mathematically forbidden from swapping these pages to `pagefile.sys`, neutralizing cold-boot and disk forensic attacks.
- **Transient Memory Sanitization (`zeroize`)**: Human passphrases and key buffers are explicitly wiped from live RAM immediately after utilization.
- **Zero-Echo Input**: Passphrase entry leverages `rpassword` to hijack CLI `stdin`, preventing terminal shoulder-surfing and shell history leaks.

### 5. Denial of Service & Parallel Scalability
- **Streamed Authenticated Encryption (Chunking)**: The cipher engine processes data iteratively in **1 Megabyte (1MB) Chunks** via `std::io` streams, keeping the memory footprint negligible, rendering Out-Of-Memory (OOM) exploits impossible.
- **Dynamic MPMC Parallel Pipeline**: Cryptographic workloads are dynamically distributed across all available logical CPU cores using a Multi-Producer Multi-Consumer (MPMC) pipeline. AES-GCM processing occurs in parallel with automatic Out-of-Order BTreeMap resequencing, scaling throughput linearly with hardware.

### 6. End-to-End Cryptographic Integrity & Forensics
- **Buffered & Flushed I/O**: Explicit OS-level synchronization (`sync_all()`) forces all write caches to physical disk, completely eliminating silent data loss at the tail-end of massive files (e.g. 20GB+).
- **Cryptographic Manifest Sealing**: After the final data chunk and EOF marker, `qcrypt` computes a full BLAKE3 hash of the plaintext and encrypts it into a cryptographic Manifest (`QCRYPTOK`), mathematically locking the file's structural integrity.
- **Tamper-Evident Decryption**: Decryption continuously calculates a rolling BLAKE3 hash. If the computed hash, chunk count, or byte count mismatches the encrypted Manifest, the process aborts securely.

### 7. Zero-Disk Network (IPFS & Arweave)
- **Direct-to-Arweave Injection (`--arweave_eth_key`)**: Supplying an Ethereum `secp256k1` private key dynamically binds `qcrypt` to the Irys/Arweave datachain. The engine will encapsulate your payloads into an `ANS-104` Deep Hash structure, cryptographically sign them with your Ethereum key, and stream them directly into the Irys L2 network for permanent Arweave L1 settlement. Absolutely zero ciphertext touches the local physical disk. The engine only drops tiny `.txid` tracker files locally, achieving perfect forensic deniability.
  - **Dynamic Enterprise Capacity Unlock**: The engine automatically caps free uploads at 100KB to protect bandwidth. However, before aborting, it mathematically derives your public `0x...` address from the key and pings the Irys Node's internal ledger. If it detects you have prepaid funded credit, it instantly unlocks unlimited heavy-upload capacities.
- **Direct-to-Swarm Injection (`--ipfs_pinata_jwt`)**: Alternatively, supplying a Pinata API JWT token implicitly routes `Keygen` and `Encrypt` operations directly into the decentralized IPFS swarm. Keys and ciphertext are piped via a zero-allocation `multipart/form-data` stream directly from RAM to the Pinata endpoints over HTTPS.
- **Direct-to-Cipher Networking**: Payloads and standard keys can be ingested directly from HTTPS URLs (`--src_net`, `--pubkey_net`, `--privkey_net`) or the decentralized IPFS swarm (`--src_ipfs`, `--privkey_ipfs`) directly into the cipher engine's RAM without ever touching the local disk. When combined with `--stego`, the engine streams the raw carrier image bytes from the network, extracts the hidden key completely in memory, and instantly drops the image buffers, achieving absolute forensic invisibility and eliminating traditional digital footprints.
- **Dynamic IPFS Gateway Scraping**: When parsing IPFS CIDs, `qcrypt` dynamically scrapes the official Protocol Labs registry to resolve the CID over live, public HTTP gateways, enabling true decentralized retrieval without the severe binary bloat of embedding a local `tokio` IPFS node.
- **Dynamic IPFS Routing (`--ipfs_gateway`)**: You have three dynamic options for gateway resolution:
  1. **Raw Tag Match (e.g. `cloudflare`)**: The engine silently scrapes the live `gateways.json` from the official `ipfs.github.io` registry, iterates through the active domain list, and dynamically builds the URL using the first gateway that matches your tag (e.g., `https://cloudflare-ipfs.com/ipfs/<CID>`).
  2. **Raw URL Override (e.g. `http://127.0.0.1:8080/`)**: The engine detects the protocol and completely bypasses the GitHub JSON scraping, manually appending `/ipfs/<CID>` to your provided URL (perfect for local nodes or private gateways).
  3. **Omitted (Default Fallback)**: If the parameter is omitted entirely, the engine skips scraping and defaults strictly to the IPFS Foundation's primary gateway (`https://ipfs.io/ipfs/<CID>`) for maximum stability and speed.

### 8. Anti-Reversing, Stealth, & Plausible Deniability
- **Full String Obfuscation**: The compiled executable contains zero readable plain-text. All internal constants, prompts, and error messages are encrypted at compile time (`obfstr`) and only decrypted ephemerally in RAM, starving reverse-engineers of structural breadcrumbs.
- **Cross-Crate Link-Time Optimization (Fat LTO)**: `qcrypt` forces aggressive monolithic inlining across all module dependencies (ML-KEM, AES, BLAKE3). This destroys standard binary boundaries and thwarts static analysis tools like IDA Pro/Ghidra.
- **Silent Operational Profile**: The core engine executes completely silently without emitting debug telemetry, protecting internal structural offsets from terminal-hooking malware.
- **Stealth Keys (Format-Fudging)**: Using the `--nopemhead` flag strips all RFC 7468 cryptographic identifiers (e.g., `-----BEGIN ENCRYPTED ML-KEM-1024 PRIVATE KEY-----`) from generated keys, outputting pure Base64 blobs. Combined with IPFS swarm separation, this grants total plausible deniability; automated scanners cannot mathematically distinguish the keys from random session tokens or corrupted configurations.
- **Stride-Dispersed LSB Steganography (`--stego`)**: The engine natively intercepts cryptographic primitives during generation or decryption, injecting or extracting the ML-KEM private key directly into/from the Least Significant Bits of lossless image carriers (PNG/BMP). This completely masks the structural existence of the key in a digital forensic sweep.

## Cryptographic Hardness (Irreversibility)

Without the corresponding `priv_key.pem` and the 16+ character passphrase, the encrypted `.enc` archive is mathematically indistinguishable from pure, irreversible random noise. The original data cannot be reconstructed:
1. **Payload Lock (AES-256)**: Brute-forcing this key requires \(2^{256}\) operations (physically impossible within the energy limits of the observable universe).
2. **Key Lock (ML-KEM-1024)**: Breaking the KEM requires solving Module Learning With Errors (MLWE) lattice problems, proven to resist state-of-the-art supercomputers and theoretical cryptographically relevant quantum computers (CRQCs).

## Threat Model: Static Keys & Perfect Forward Secrecy (PFS)

`qcrypt` operates using **Static Key Pairs**, meaning you generate a permanent `priv_key.pem` and use the matching public key to encrypt payloads over an extended period. This inherently breaks **Perfect Forward Secrecy (PFS)**. 

If an adversary captures your encrypted payloads today ("Harvest Now") and physically compromises your YubiKey or extracts your static `priv_key.pem` five years from now, they can retroactively decrypt all historical payloads locked to that key.

**Mandatory Mitigation (Key Rotation)**: To simulate PFS in static file encryption, you must implement strict Key Rotation. Generate a new ML-KEM key pair annually or per-project. Stop encrypting new payloads to the old public key, and permanently destroy the old private key once its encrypted payloads are no longer needed.

## Command Line Usage (CLI)

The `qcrypt.exe` binary requires no installation or external runtime dependencies. 

### 1. Key Generation
Generates a Post-Quantum Key Pair. You can pass your passphrase directly via `--pass` or omit it to be prompted silently. Use `--yubikey` to enforce hardware-only access, or `--yubikey_and_pass` for hardware + passphrase MFA. Use `--nopemhead` to generate headerless Stealth Keys. Provide `--stego` to instantly bake the key into a carrier image upon generation. Provide `--ipfs_pinata_jwt` to push keys directly to IPFS, or `--arweave_eth_key` to upload them to the Arweave permaweb.
```bash
qcrypt keygen [--pass <16_char_password>] [--yubikey] [--yubikey_and_pass] [--nopemhead] [--stego <CARRIER_PNG>] [--ipfs_pinata_jwt <TOKEN>] [--arweave_eth_key <PATH>]
```

### 2. Encryption
Encrypts a target payload. You must specify the source of the payload and can optionally override the public key location and output filename. Provide `--ipfs_pinata_jwt` or `--arweave_eth_key` to stream the ciphertext directly to the respective decentralized network.
```bash
qcrypt encrypt [--src_loc <PATH> | --src_net <URL> | --src_ipfs <CID>]
               [--pubkey_loc <PATH> | --pubkey_net <URL> | --pubkey_ipfs <CID>]
               [--tgt_loc <OUTPUT_PATH>]
               [--ipfs_gateway <TAG_OR_URL>]
               [--ipfs_pinata_jwt <TOKEN>]
               [--arweave_eth_key <PATH>]
```

### 3. Decryption
Decrypts an archive using the matching private key. You can stream the encrypted archive and the private key from any location. Provide `--yubikey` or `--yubikey_and_pass` to authorize using your hardware token.
```bash
qcrypt decrypt [--src_loc <PATH> | --src_net <URL> | --src_ipfs <CID>]
               [--privkey_loc <PATH> | --privkey_net <URL> | --privkey_ipfs <CID>]
               [--pass <16_char_password>] [--yubikey] [--yubikey_and_pass]
               [--tgt_loc <OUTPUT_PATH>]
               [--ipfs_gateway <TAG_OR_URL>]
               [--stego]
```

### 4. Forensic Scan & Public Key Recovery
Scans an encrypted archive for structural corruption or truncation (e.g., from network interruptions or bad sectors) without requiring the private key.
```bash
qcrypt forensic <path_to_file.enc>
```

Alternatively, use the forensic tool to mathematically regenerate a lost public key directly from its corresponding private key. This supports all advanced retrieval methods (IPFS, Network, Stego, YubiKey).
```bash
qcrypt forensic --keygen_pub [--privkey_net <URL> | --privkey_loc <PATH> | --privkey_ipfs <CID>]
                             [--pass <string>] [--yubikey] [--yubikey_and_pass]
                             [--stego] [--nopemhead] [--tgt_loc <PATH>]
```

### 5. Graphical User Interface (GUI)
Launches the native desktop graphical interface. The GUI encapsulates all CLI cryptographic primitives, Tri-Mode YubiKey authentication, and zero-disk network bindings (IPFS, Arweave) into a streamlined, cross-platform dashboard. It features a persistent `log_status` terminal that retains cryptographic execution telemetry across all operation tabs dynamically.
```bash
qcrypt gui
```

### 6. Steganography Toolkit
Raw LSB steganography engine for manipulating keys inside PNG/BMP carrier images natively without triggering a full encryption/decryption pipeline.
```bash
qcrypt stego [--inject | --extract] [--src_loc <PATH>] [--privkey_loc <PATH>] [--tgt_loc <PATH>]
```

### 7. YubiKey Provisioning
Generate a deterministic 40-character Hex HMAC-SHA1 secret backed by Argon2id to instantly program your physical YubiKey (Slot 2) using `ykman`.
```bash
qcrypt yubikey --genhmacsha1 [--pass <16_char_passphrase>] [--tgt_loc <PATH>]

# Import the generated file contents into your YubiKey:
# (Replace <40_char_hex> with the actual hex string from the file)
ykman otp chalresp 2 <40_char_hex>

# To explicitly require a physical touch for every authentication:
ykman otp chalresp -t 2 <40_char_hex>

# To inject the hex directly from the generated file:
# PowerShell:
ykman otp chalresp 2 $(Get-Content hmac_sha1_key.hex)

# Linux/Mac:
ykman otp chalresp 2 $(cat hmac_sha1_key.hex)
```
