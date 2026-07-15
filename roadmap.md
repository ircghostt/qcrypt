# qcrypt Strategic Roadmap

The baseline architecture (ML-KEM-1024 + AES-256-GCM + memory hardness) establishes an elite, production-ready cryptographic core. To escalate into the realm of extreme operational security (OPSEC) and counter-extortion, the following advanced vectors are slated for future exploration:

## 1. Steganographic Integration (Carrier Injection)
**Objective**: Defeat signature and traffic analysis.
Currently, an attacker scanning the disk knows they are looking at encrypted data (`.enc` or Base64 blobs). By injecting the ciphertext and keys directly into the noise channels of high-resolution `.jpg` or `.mp4` media files, the payload becomes mathematically invisible. The adversary remains unaware that encryption is even present.

## 2. Plausible Deniability (Rubber-Hose Defense)
**Objective**: Neutralize physical coercion and extortion.
Implement a decoy payload mechanism. `qcrypt` will append a secondary, independent encrypted payload within the same file structure. If physically coerced, the user surrenders a "decoy passphrase" that cleanly decrypts benign data, while the true classified payload remains mathematically indistinguishable from the surrounding random noise.

## 3. Hardware Token Binding (FIDO2 / YubiKey)
**Objective**: Enforce physical presence requirements.
Currently, the private key is locked solely by Argon2id memory-hardness. This vector integrates PKCS#11/FIDO2 bindings, requiring the physical presence of a hardware token (e.g., YubiKey) injected into the USB port to finalize the decryption pipeline, eliminating remote decryption capabilities even if the passphrase is compromised.

## 4. M-of-N Key Splitting (Shamir's Secret Sharing)
**Objective**: Eliminate single points of physical failure.
Implement a mode to mathematically split the `priv_key.pem` into `N` distinct shards (e.g., 5 shards), requiring a minimum threshold of `M` (e.g., 3 shards) to reconstruct the key. Distributing these shards across disparate environments (e.g., 3 to IPFS, 1 to Arweave, 1 to local disk) completely neutralizes physical extortion or localized hardware compromise.

## 5. Air-Gapped Optical Transit (QR Sequencing)
**Objective**: Absolute network isolation.
For physically isolated, air-gapped machines, this vector converts keys and ciphertext chunks into a rapid sequence of QR codes. A webcam on a networked machine scans the sequence to transit the data without ever bridging a network cable or mounting a USB drive across the air-gap.
