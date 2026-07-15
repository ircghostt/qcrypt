use sha2::{Digest, Sha384};
use sha3::Keccak256;
use secp256k1::{Message, Secp256k1, SecretKey};
use std::fs;
use std::str::FromStr;

pub enum DeepHashChunk {
    Chunk(Vec<u8>),
    Chunks(Vec<DeepHashChunk>),
}

fn sha384hash(b: &[u8]) -> Vec<u8> {
    let mut hasher = Sha384::new();
    hasher.update(b);
    hasher.finalize().to_vec()
}

pub fn deep_hash_sync(chunk: DeepHashChunk) -> Vec<u8> {
    match chunk {
        DeepHashChunk::Chunk(b) => {
            let tag = format!("blob{}", b.len());
            let c = [sha384hash(tag.as_bytes()), sha384hash(&b)].concat();
            sha384hash(&c)
        }
        DeepHashChunk::Chunks(chunks) => {
            let len = chunks.len();
            let tag = format!("list{}", len);
            let acc = sha384hash(tag.as_bytes());
            deep_hash_chunks_sync(chunks, acc)
        }
    }
}

fn deep_hash_chunks_sync(mut chunks: Vec<DeepHashChunk>, acc: Vec<u8>) -> Vec<u8> {
    if chunks.is_empty() {
        return acc;
    }
    let next_chunk = chunks.remove(0);
    let hash_pair = [acc, deep_hash_sync(next_chunk)].concat();
    let new_acc = sha384hash(&hash_pair);
    deep_hash_chunks_sync(chunks, new_acc)
}

pub fn eth_hash_message(msg: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
    let data = [prefix.as_bytes(), msg].concat();
    let mut hasher = Keccak256::new();
    hasher.update(&data);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hasher.finalize());
    result
}

pub fn sign_and_build_dataitem(data: &[u8], eth_key_hex: &str) -> Result<Vec<u8>, String> {
    let hex_clean = eth_key_hex.trim_start_matches("0x").trim();
    let secret_key = SecretKey::from_str(hex_clean).map_err(|e| e.to_string())?;
    let secp = Secp256k1::new();
    let pub_key = secret_key.public_key(&secp);
    let owner_bytes = pub_key.serialize_uncompressed().to_vec();
    
    let data_chunk = DeepHashChunk::Chunk(data.to_vec());
    let chunks = vec![
        DeepHashChunk::Chunk(b"dataitem".to_vec()),
        DeepHashChunk::Chunk(b"1".to_vec()),
        DeepHashChunk::Chunk(b"3".to_vec()),
        DeepHashChunk::Chunk(owner_bytes.clone()),
        DeepHashChunk::Chunk(vec![]),
        DeepHashChunk::Chunk(vec![]),
        DeepHashChunk::Chunk(vec![]),
        data_chunk
    ];
    
    let deep_hash = deep_hash_sync(DeepHashChunk::Chunks(chunks));
    
    let msg_hash = eth_hash_message(&deep_hash);
    let message = Message::from_digest(msg_hash);
    let (recovery_id, sig_bytes) = secp.sign_ecdsa_recoverable(message, &secret_key).serialize_compact();
    
    let mut signature = sig_bytes.to_vec();
    signature.push(i32::from(recovery_id) as u8 + 27);
    
    let mut out = Vec::new();
    out.extend_from_slice(&3u16.to_le_bytes()); 
    out.extend_from_slice(&signature);
    out.extend_from_slice(&owner_bytes);
    out.push(0); 
    out.push(0); 
    out.extend_from_slice(&0u64.to_le_bytes()); 
    out.extend_from_slice(&0u64.to_le_bytes()); 
    out.extend_from_slice(data);
    
    Ok(out)
}

pub fn upload_to_irys(data: &[u8], eth_key_source: &str) -> Result<String, String> {
    let hex_str = if std::path::Path::new(eth_key_source).exists() {
        fs::read_to_string(eth_key_source).map_err(|e| e.to_string())?
    } else {
        eth_key_source.to_string()
    };
    
    let dataitem = sign_and_build_dataitem(data, &hex_str)?;
    
    let resp = ureq::post("https://uploader.irys.xyz/tx/ethereum")
        .set("Content-Type", "application/octet-stream")
        .send_bytes(&dataitem);
        
    match resp {
        Ok(res) => {
            let body = res.into_string().unwrap_or_default();
            Ok(body)
        },
        Err(ureq::Error::Status(code, res)) => {
            Err(format!("Irys upload failed with status {}: {}", code, res.into_string().unwrap_or_default()))
        },
        Err(e) => Err(e.to_string())
    }
}

pub fn resolve_arweave_url(url: &str) -> Result<ureq::Response, String> {
    let txid = url.split("://").last().unwrap_or(url);
    let irys_url = format!("https://gateway.irys.xyz/{}", txid);
    let ar_url = format!("https://gateway.arweave.net/{}", txid);
    
    match ureq::get(&irys_url).call() {
        Ok(resp) => Ok(resp),
        Err(_) => {
            println!("Irys L2 Gateway miss. Falling back to Arweave L1 Gateway...");
            ureq::get(&ar_url).call().map_err(|e| format!("Failed to fetch from both Irys and Arweave gateways: {}", e))
        }
    }
}

pub fn has_irys_balance(eth_key_hex: &str) -> bool {
    let secp = secp256k1::Secp256k1::new();
    if let Ok(secret_key) = secp256k1::SecretKey::from_str(eth_key_hex) {
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let serialized = public_key.serialize_uncompressed();
        
        let mut hasher = sha3::Keccak256::new();
        hasher.update(&serialized[1..]);
        let hash = hasher.finalize();
        let address_bytes = &hash[12..];
        let address = format!("0x{}", hex::encode(address_bytes));
        
        let url = format!("https://uploader.irys.xyz/account/balance/ethereum?address={}", address);
        if let Ok(resp) = ureq::get(&url).call() {
            if let Ok(json_str) = resp.into_string() {
                if let Some(balance_str) = json_str.split("\"balance\":\"").nth(1) {
                    if let Some(val_str) = balance_str.split("\"").next() {
                        if let Ok(val) = val_str.parse::<u64>() {
                            return val > 0;
                        }
                    }
                }
            }
        }
    }
    false
}
