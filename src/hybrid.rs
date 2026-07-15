use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    Aes256Gcm, Nonce
};
use ml_kem::{MlKem1024, KemCore, kem::{Encapsulate, Decapsulate}};
use ml_kem::EncodedSizeUser;
use rand::rngs::OsRng;
use rand::RngCore;
use hkdf::Hkdf;
use sha2::Sha256;
use pem::Pem;
use std::io::{Read, Write, BufReader};
use argon2::Argon2;
use crossbeam_channel::bounded;

#[derive(Debug, Clone, PartialEq, Default)]
pub enum AuthMode {
    #[default]
    Passphrase,
    HardwareOnly,
    HardwareAndPassphrase,
}



pub type EncapsulatingKey = <MlKem1024 as KemCore>::EncapsulationKey;
pub type DecapsulatingKey = <MlKem1024 as KemCore>::DecapsulationKey;

const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB
const MANIFEST_MAGIC: &[u8; 8] = b"QCRYPTOK";

// ─── Key Generation ─────────────────────────────────────────────

pub fn generate_keys(password: &str, nopemhead: bool, auth_mode: &AuthMode) -> (String, String) {
    let mut rng = OsRng;
    let (decaps_key, encaps_key) = MlKem1024::generate(&mut rng);
    
    let mut priv_bytes = decaps_key.as_bytes().as_slice().to_vec();
    unsafe { memsec::mlock(priv_bytes.as_mut_ptr(), priv_bytes.len()); }
    
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);
    
    let entropy = match auth_mode {
        AuthMode::Passphrase => password.as_bytes().to_vec(),
        AuthMode::HardwareOnly => crate::yubikey::yubikey_challenge(&salt).unwrap_or_else(|e| { eprintln!("{}", e); std::process::exit(1); }),
        AuthMode::HardwareAndPassphrase => {
            let mut ent = password.as_bytes().to_vec();
            ent.extend_from_slice(&crate::yubikey::yubikey_challenge(&salt).unwrap_or_else(|e| { eprintln!("{}", e); std::process::exit(1); }));
            ent
        }
    };
    
    let mut argon_aes_key = [0u8; 32];
    unsafe { memsec::mlock(argon_aes_key.as_mut_ptr(), 32); }
    
    Argon2::default().hash_password_into(&entropy, &salt, &mut argon_aes_key).expect("Argon2id derivation failed");
    
    let cipher = Aes256Gcm::new_from_slice(&argon_aes_key).unwrap();
    let nonce = Aes256Gcm::generate_nonce(&mut rng);
    
    let payload = Payload { msg: &priv_bytes, aad: &[] };
    let encrypted_priv = cipher.encrypt(&nonce, payload).expect("Private key encryption failed");
    
    let mut final_payload = Vec::with_capacity(16 + 12 + encrypted_priv.len());
    final_payload.extend_from_slice(&salt);
    final_payload.extend_from_slice(nonce.as_slice());
    final_payload.extend_from_slice(&encrypted_priv);
    
    let priv_out = if nopemhead {
        let full_pem = pem::encode(&Pem::new("ENCRYPTED ML-KEM-1024 PRIVATE KEY", final_payload));
        full_pem.lines().filter(|l| !l.starts_with("-----")).collect::<Vec<_>>().join("\n") + "\n"
    } else {
        pem::encode(&Pem::new("ENCRYPTED ML-KEM-1024 PRIVATE KEY", final_payload))
    };
    
    let pub_out = if nopemhead {
        let full_pem = pem::encode(&Pem::new("ML-KEM-1024 PUBLIC KEY", encaps_key.as_bytes().as_slice()));
        full_pem.lines().filter(|l| !l.starts_with("-----")).collect::<Vec<_>>().join("\n") + "\n"
    } else {
        pem::encode(&Pem::new("ML-KEM-1024 PUBLIC KEY", encaps_key.as_bytes().as_slice()))
    };
    
    unsafe {
        memsec::memzero(priv_bytes.as_mut_ptr(), priv_bytes.len());
        memsec::munlock(priv_bytes.as_mut_ptr(), priv_bytes.len());
        memsec::memzero(argon_aes_key.as_mut_ptr(), 32);
        memsec::munlock(argon_aes_key.as_mut_ptr(), 32);
    }
    
    (priv_out, pub_out)
}

// ─── Stealth Parsing Helper ─────────────────────────────────────

pub fn parse_key_blob(blob: &str) -> Result<Vec<u8>, &'static str> {
    let blob = blob.trim();
    if blob.starts_with("-----BEGIN") {
        let pem = pem::parse(blob).map_err(|_| "Invalid PEM format")?;
        Ok(pem.contents().to_vec())
    } else {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let clean_blob = blob.replace(&['\n', '\r', ' '][..], "");
        STANDARD.decode(&clean_blob).map_err(|_| "Invalid Base64 Stealth format")
    }
}

// ─── Nonce Derivation ───────────────────────────────────────────

fn derive_chunk_nonce(base_nonce: &[u8; 12], chunk_idx: u64) -> [u8; 12] {
    let mut nonce = *base_nonce;
    let idx_bytes = chunk_idx.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= idx_bytes[i];
    }
    nonce
}


// ─── Encryption ─────────────────────────────────────────────────

use std::thread;
use std::collections::BTreeMap;

use indicatif::{ProgressBar, ProgressStyle};

pub fn encrypt_stream<W: Write + Send + 'static>(
    input: impl Read + Send + 'static,
    mut output: W,
    pub_key_pem: &str
) -> Result<W, &'static str> {
    let mut rng = OsRng;
    let mut input = BufReader::with_capacity(CHUNK_SIZE * 2, input);
    
    let pub_key_vec = parse_key_blob(pub_key_pem)?;
    let pub_key_arr = pub_key_vec.as_slice().try_into().map_err(|_| "Invalid public key size")?;
    let public_key = EncapsulatingKey::from_bytes(&pub_key_arr);
    
    let (ciphertext, mut shared_secret) = public_key.encapsulate(&mut rng).map_err(|_| "Encapsulation failed")?;
    
    unsafe { memsec::mlock(shared_secret.as_mut_slice().as_mut_ptr(), 32); }
    
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_slice());
    let mut hkdf_aes_key = [0u8; 32];
    unsafe { memsec::mlock(hkdf_aes_key.as_mut_ptr(), 32); }
    
    hkdf.expand(obfstr::obfstr!("qcrypt-aes-gcm").as_bytes(), &mut hkdf_aes_key).map_err(|_| "HKDF expansion failed")?;
    
    let base_nonce = Aes256Gcm::generate_nonce(&mut rng);
    let base_nonce_bytes: [u8; 12] = base_nonce.as_slice().try_into().unwrap();
    
    let kem_ct_bytes = ciphertext.as_slice();
    let header_size = kem_ct_bytes.len() + 12;
    
    let mut aad = Vec::with_capacity(kem_ct_bytes.len() + 12);
    aad.extend_from_slice(kem_ct_bytes);
    aad.extend_from_slice(&base_nonce_bytes);
    
    output.write_all(kem_ct_bytes).map_err(|_| "I/O error writing headers")?;
    output.write_all(&base_nonce_bytes).map_err(|_| "I/O error writing nonce")?;
    
    let num_workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let (work_tx, work_rx) = bounded::<(u64, Vec<u8>, [u8; 12])>(num_workers * 2);
    let (out_tx, out_rx) = bounded::<(u64, Vec<u8>)>(num_workers * 2);
    
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{bytes_per_sec}] {bytes} encrypted")
        .unwrap()
        .progress_chars("#>-"));
    
        let mut handles = vec![];
    
    for _ in 0..num_workers {
        let rx = work_rx.clone();
        let tx = out_tx.clone();
        let key = hkdf_aes_key.clone();
        let aad = aad.clone();
        
        let handle = thread::spawn(move || {
            let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
            while let Ok((chunk_idx, buffer, chunk_nonce)) = rx.recv() {
                let chunk_nonce_ref = Nonce::from_slice(&chunk_nonce);
                let payload = Payload {
                    msg: &buffer[..],
                    aad: &aad, 
                };
                let encrypted_chunk = cipher.encrypt(chunk_nonce_ref, payload).unwrap();
                tx.send((chunk_idx, encrypted_chunk)).unwrap();
            }
        });
        handles.push(handle);
    }
    
    drop(out_tx); // Drop original out_tx so writer finishes when workers finish
    
    let writer_handle = thread::spawn(move || {
        let mut total_written: u64 = header_size as u64;
        let mut next_expected: u64 = 0;
        let mut pending = BTreeMap::new();
        
        while let Ok((chunk_idx, encrypted_chunk)) = out_rx.recv() {
            pending.insert(chunk_idx, encrypted_chunk);
            
            while let Some(chunk) = pending.remove(&next_expected) {
                let chunk_wire_len = chunk.len() as u32;
                output.write_all(&chunk_wire_len.to_be_bytes()).unwrap();
                output.write_all(&chunk).unwrap();
                total_written += 4 + chunk.len() as u64;
                pb.inc((chunk.len() - 16) as u64); // rough plaintext size
                next_expected += 1;
            }
        }
        
        (output, total_written, next_expected, pb)
    });
    
    let mut plaintext_hasher = blake3::Hasher::new();
    let mut chunk_idx: u64 = 0;
    let mut total_bytes_read: u64 = 0;
    
    loop {
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut bytes_read = 0;
        while bytes_read < CHUNK_SIZE {
            match input.read(&mut buffer[bytes_read..]) {
                Ok(0) => break,
                Ok(n) => bytes_read += n,
                Err(_) => return Err("I/O error reading input"),
            }
        }
        
        if bytes_read == 0 {
            break;
        }
        
        buffer.truncate(bytes_read);
        
        plaintext_hasher.update(&buffer);
        total_bytes_read += bytes_read as u64;
        
        let chunk_nonce = derive_chunk_nonce(&base_nonce_bytes, chunk_idx);
        work_tx.send((chunk_idx, buffer, chunk_nonce)).unwrap();
        
        chunk_idx += 1;
    }
    
    drop(work_tx); // Signal workers to stop
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    let (mut output, mut _total_bytes_written, next_expected, pb) = writer_handle.join().unwrap();
    
    assert_eq!(chunk_idx, next_expected);
    pb.finish_with_message("Encryption complete");
    
    let cipher = Aes256Gcm::new_from_slice(&hkdf_aes_key).unwrap();
    
    // EOF Marker
    let eof_nonce = derive_chunk_nonce(&base_nonce_bytes, chunk_idx);
    let eof_nonce_ref = Nonce::from_slice(&eof_nonce);
    let eof_payload = Payload { msg: &[][..], aad: &aad };
    let eof_chunk = cipher.encrypt(eof_nonce_ref, eof_payload).map_err(|_| "AES encryption failed on EOF chunk")?;
    output.write_all(&(eof_chunk.len() as u32).to_be_bytes()).unwrap();
    output.write_all(&eof_chunk).unwrap();
    _total_bytes_written += 4 + eof_chunk.len() as u64;
    
    // Manifest
    let plaintext_hash = plaintext_hasher.finalize();
    let plaintext_hash_bytes = plaintext_hash.as_bytes();
    let mut manifest = Vec::with_capacity(48);
    manifest.extend_from_slice(MANIFEST_MAGIC);
    manifest.extend_from_slice(&chunk_idx.to_be_bytes());
    manifest.extend_from_slice(&total_bytes_read.to_be_bytes());
    manifest.extend_from_slice(plaintext_hash_bytes);
    
    let manifest_nonce = derive_chunk_nonce(&base_nonce_bytes, chunk_idx + 1);
    let manifest_nonce_ref = Nonce::from_slice(&manifest_nonce);
    let manifest_payload = Payload { msg: &manifest, aad: &aad };
    let manifest_chunk = cipher.encrypt(manifest_nonce_ref, manifest_payload).map_err(|_| "AES encryption failed on manifest")?;
    output.write_all(&(manifest_chunk.len() as u32).to_be_bytes()).unwrap();
    output.write_all(&manifest_chunk).unwrap();
    _total_bytes_written += 4 + manifest_chunk.len() as u64;
    
    output.flush().unwrap();
    
    unsafe {
        memsec::memzero(shared_secret.as_mut_slice().as_mut_ptr(), 32);
        memsec::munlock(shared_secret.as_mut_slice().as_mut_ptr(), 32);
        memsec::memzero(hkdf_aes_key.as_mut_ptr(), 32);
        memsec::munlock(hkdf_aes_key.as_mut_ptr(), 32);
    }
    
    Ok(output)
}
pub fn decrypt_stream(
    input: impl Read + Send + 'static,
    mut output: impl Write + Send + 'static,
    priv_key_pem: &str,
    password: &str,
    auth_mode: &AuthMode
) -> Result<(), String> {
    let mut input = BufReader::with_capacity(CHUNK_SIZE * 2, input);

    // ── Unlock private key ──
    let enc_payload = parse_key_blob(priv_key_pem)?;
    
    if enc_payload.len() < 16 + 12 + 16 {
        return Err("Encrypted private key payload too small".to_string());
    }
    
    let salt = &enc_payload[0..16];
    let priv_nonce_bytes = &enc_payload[16..28];
    let priv_ciphertext = &enc_payload[28..];
    
    let mut argon_aes_key = [0u8; 32];
    unsafe { memsec::mlock(argon_aes_key.as_mut_ptr(), 32); }
    
    let entropy = match auth_mode {
        AuthMode::Passphrase => password.as_bytes().to_vec(),
        AuthMode::HardwareOnly => crate::yubikey::yubikey_challenge(salt)?,
        AuthMode::HardwareAndPassphrase => {
            let mut ent = password.as_bytes().to_vec();
            ent.extend_from_slice(&crate::yubikey::yubikey_challenge(salt)?);
            ent
        }
    };
    
    Argon2::default().hash_password_into(&entropy, salt, &mut argon_aes_key).map_err(|_| "Argon2id failed".to_string())?;
    
    let priv_cipher = Aes256Gcm::new_from_slice(&argon_aes_key).unwrap();
    let priv_nonce = Nonce::from_slice(priv_nonce_bytes);
    
    let payload = Payload { msg: priv_ciphertext, aad: &[] };
    let mut priv_key_vec = priv_cipher.decrypt(priv_nonce, payload).map_err(|_| "Incorrect passphrase or corrupted private key".to_string())?;
    
    unsafe { memsec::mlock(priv_key_vec.as_mut_ptr(), priv_key_vec.len()); }
    let private_key = DecapsulatingKey::from_bytes(priv_key_vec.as_slice().try_into().map_err(|_| "Invalid decrypted key size".to_string())?);
    
    // ── Read header ──
    let mut kem_ciphertext = [0u8; 1568];
    input.read_exact(&mut kem_ciphertext).map_err(|_| "Archive too small: Missing KEM header".to_string())?;
    
    let mut base_nonce_bytes = [0u8; 12];
    input.read_exact(&mut base_nonce_bytes).map_err(|_| "Archive too small: Missing Nonce header".to_string())?;
    
    let ct: ml_kem::Ciphertext<MlKem1024> = kem_ciphertext.try_into().map_err(|_| "Invalid KEM ciphertext length".to_string())?;
    let mut shared_secret = private_key.decapsulate(&ct).map_err(|_| "Decapsulation failed".to_string())?;
    
    unsafe { memsec::mlock(shared_secret.as_mut_slice().as_mut_ptr(), 32); }
    
    let hkdf = Hkdf::<sha2::Sha256>::new(None, shared_secret.as_slice());
    let mut hkdf_aes_key = [0u8; 32];
    unsafe { memsec::mlock(hkdf_aes_key.as_mut_ptr(), 32); }
    hkdf.expand(obfstr::obfstr!("qcrypt-aes-gcm").as_bytes(), &mut hkdf_aes_key).map_err(|_| "HKDF expansion failed".to_string())?;
    
    let mut aad = Vec::with_capacity(1568 + 12);
    aad.extend_from_slice(&kem_ciphertext);
    aad.extend_from_slice(&base_nonce_bytes);

    let num_workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let (work_tx, work_rx) = crossbeam_channel::bounded::<(u64, Vec<u8>, [u8; 12], u64)>(num_workers * 2);
    let (out_tx, out_rx) = crossbeam_channel::bounded::<(u64, Result<(Vec<u8>, u64), String>)>(num_workers * 2);
    
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{bytes_per_sec}] {bytes} decrypted")
        .unwrap()
        .progress_chars("#>-"));

    let mut handles = vec![];
    for _ in 0..num_workers {
        let rx = work_rx.clone();
        let tx = out_tx.clone();
        let key = hkdf_aes_key.clone();
        let aad = aad.clone();
        
        let handle = std::thread::spawn(move || {
            let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
            while let Ok((chunk_idx, buffer, chunk_nonce, file_offset)) = rx.recv() {
                let chunk_nonce_ref = Nonce::from_slice(&chunk_nonce);
                let payload = Payload {
                    msg: &buffer[..],
                    aad: &aad,
                };
                match cipher.decrypt(chunk_nonce_ref, payload) {
                    Ok(dec) => tx.send((chunk_idx, Ok((dec, file_offset)))).unwrap(),
                    Err(_) => tx.send((chunk_idx, Err(format!("AES authentication FAILED at offset {}", file_offset)))).unwrap(),
                }
            }
        });
        handles.push(handle);
    }
    
    drop(out_tx);

    let pb_writer = pb.clone();
    let writer_handle = std::thread::spawn(move || -> Result<_, String> {
        let mut total_decrypted: u64 = 0;
        let mut next_expected: u64 = 0;
        let mut pending = std::collections::BTreeMap::new();
        let mut plaintext_hasher = blake3::Hasher::new();
        
        let mut eof_found = false;
        let mut eof_chunk_idx = 0;
        
        while let Ok((chunk_idx, result)) = out_rx.recv() {
            pending.insert(chunk_idx, result);
            
            while let Some(res) = pending.remove(&next_expected) {
                let (decrypted_chunk, _file_offset) = res?;
                
                if !eof_found {
                    if decrypted_chunk.is_empty() {
                        eof_found = true;
                        eof_chunk_idx = next_expected;
                    } else {
                        plaintext_hasher.update(&decrypted_chunk);
                        output.write_all(&decrypted_chunk).map_err(|e| format!("Write error: {}", e))?;
                        total_decrypted += decrypted_chunk.len() as u64;
                        pb_writer.inc(decrypted_chunk.len() as u64);
                    }
                } else {
                    if next_expected == eof_chunk_idx + 1 {
                        output.flush().unwrap();
                        return Ok((output, total_decrypted, plaintext_hasher, decrypted_chunk, eof_chunk_idx));
                    }
                }
                next_expected += 1;
            }
        }
        Err("Archive truncated without EOF marker".to_string())
    });

    let mut chunk_idx: u64 = 0;
    let mut file_offset: u64 = 1580;
    
    loop {
        let mut len_bytes = [0u8; 4];
        if input.read_exact(&mut len_bytes).is_err() {
            break;
        }
        let chunk_len = u32::from_be_bytes(len_bytes) as usize;
        file_offset += 4;
        
        let mut buffer = vec![0u8; chunk_len];
        if input.read_exact(&mut buffer).is_err() {
            break;
        }
        
        let chunk_nonce = derive_chunk_nonce(&base_nonce_bytes, chunk_idx);
        work_tx.send((chunk_idx, buffer, chunk_nonce, file_offset)).unwrap();
        
        file_offset += chunk_len as u64;
        chunk_idx += 1;
    }
    
    drop(work_tx);
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    let (_output, total_decrypted, plaintext_hasher, manifest_bytes, eof_chunk_idx) = writer_handle.join().unwrap()?;
    pb.finish_with_message("Decryption complete");

    // Verify manifest
    let computed_hash = plaintext_hasher.finalize();
    let computed_hash_bytes = computed_hash.as_bytes();
    
    if manifest_bytes.len() < 48 {
        return Err("Manifest chunk too small".to_string());
    }
    
    let magic = &manifest_bytes[0..8];
    let m_chunk_idx = u64::from_be_bytes(manifest_bytes[8..16].try_into().unwrap());
    let m_bytes = u64::from_be_bytes(manifest_bytes[16..24].try_into().unwrap());
    let m_hash = &manifest_bytes[24..56];
    
    if magic != MANIFEST_MAGIC {
        return Err("Invalid manifest magic bytes".to_string());
    }
    if m_chunk_idx != eof_chunk_idx {
        return Err(format!("Chunk count mismatch: expected {}, got {}", eof_chunk_idx, m_chunk_idx));
    }
    if m_bytes != total_decrypted {
        return Err(format!("Byte count mismatch: expected {}, got {}", total_decrypted, m_bytes));
    }
    if m_hash != computed_hash_bytes {
        return Err("BLAKE3 MISMATCH: The file data has been corrupted or tampered with!".to_string());
    }

    unsafe {
        memsec::memzero(argon_aes_key.as_mut_ptr(), 32);
        memsec::munlock(argon_aes_key.as_mut_ptr(), 32);
        memsec::memzero(hkdf_aes_key.as_mut_ptr(), 32);
        memsec::munlock(hkdf_aes_key.as_mut_ptr(), 32);
    }
    
    Ok(())
}

// ─── Public Key Recovery ────────────────────────────────────────

pub fn recover_public_key(
    priv_key_pem: &str,
    password: &str,
    auth_mode: &AuthMode,
    nopemhead: bool
) -> Result<String, String> {
    let enc_payload = parse_key_blob(priv_key_pem)?;
    
    if enc_payload.len() < 16 + 12 + 16 {
        return Err("Encrypted private key payload too small".to_string());
    }
    
    let salt = &enc_payload[0..16];
    let priv_nonce_bytes = &enc_payload[16..28];
    let priv_ciphertext = &enc_payload[28..];
    
    let mut argon_aes_key = [0u8; 32];
    unsafe { memsec::mlock(argon_aes_key.as_mut_ptr(), 32); }
    
    let entropy = match auth_mode {
        AuthMode::Passphrase => password.as_bytes().to_vec(),
        AuthMode::HardwareOnly => crate::yubikey::yubikey_challenge(salt)?,
        AuthMode::HardwareAndPassphrase => {
            let mut ent = password.as_bytes().to_vec();
            ent.extend_from_slice(&crate::yubikey::yubikey_challenge(salt)?);
            ent
        }
    };
    
    Argon2::default().hash_password_into(&entropy, salt, &mut argon_aes_key).map_err(|_| "Argon2id failed".to_string())?;
    
    let priv_cipher = Aes256Gcm::new_from_slice(&argon_aes_key).unwrap();
    let priv_nonce = Nonce::from_slice(priv_nonce_bytes);
    
    let payload = Payload { msg: priv_ciphertext, aad: &[] };
    let mut priv_key_vec = priv_cipher.decrypt(priv_nonce, payload).map_err(|_| "Incorrect passphrase or corrupted private key".to_string())?;
    
    // In ML-KEM-1024, the FIPS 203 Decapsulation Key is exactly 3168 bytes.
    // The format is: s (1536 bytes) || ek (1568 bytes) || H(ek) (32 bytes) || z (32 bytes)
    // We slice out the Encapsulation Key (Public Key) directly from the raw bytes.
    if priv_key_vec.len() != 3168 {
        return Err("Invalid decrypted private key size (expected 3168 bytes for ML-KEM-1024)".to_string());
    }
    
    let pub_key_bytes = &priv_key_vec[1536..1536 + 1568];
    
    let pub_out = if nopemhead {
        let full_pem = pem::encode(&Pem::new("ML-KEM-1024 PUBLIC KEY", pub_key_bytes));
        full_pem.lines().filter(|l| !l.starts_with("-----")).collect::<Vec<_>>().join("\n") + "\n"
    } else {
        pem::encode(&Pem::new("ML-KEM-1024 PUBLIC KEY", pub_key_bytes))
    };
    
    unsafe {
        memsec::memzero(priv_key_vec.as_mut_ptr(), priv_key_vec.len());
        memsec::memzero(argon_aes_key.as_mut_ptr(), 32);
        memsec::munlock(argon_aes_key.as_mut_ptr(), 32);
    }
    
    Ok(pub_out)
}

