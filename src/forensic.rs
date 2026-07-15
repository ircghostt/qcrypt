use std::io::{Read, BufReader};
use std::fs::File;
use std::path::PathBuf;

const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB
const MAX_ENCRYPTED_CHUNK: usize = CHUNK_SIZE + 16;
const KEM_CT_SIZE: u64 = 1568;
const NONCE_SIZE: u64 = 12;
const HEADER_SIZE: u64 = KEM_CT_SIZE + NONCE_SIZE;

pub fn forensic_scan(path: &PathBuf) -> Result<(), String> {
    let file = File::open(path).map_err(|e| format!("Cannot open file: {}", e))?;
    let file_size = file.metadata().map_err(|e| format!("Cannot read metadata: {}", e))?.len();
    let mut reader = BufReader::with_capacity(CHUNK_SIZE * 2, file);

    eprintln!("=== QCRYPT FORENSIC SCANNER ===");
    eprintln!("File: {:?}", path);
    eprintln!("File size: {} bytes ({:.2} GB)", file_size, file_size as f64 / 1_073_741_824.0);
    eprintln!();

    if file_size < HEADER_SIZE {
        return Err(format!("File too small for header: {} < {}", file_size, HEADER_SIZE));
    }
    let mut header_buf = vec![0u8; HEADER_SIZE as usize];
    reader.read_exact(&mut header_buf).map_err(|e| format!("Cannot read header: {}", e))?;
    eprintln!("[HEADER] KEM ciphertext ({} bytes) + nonce ({} bytes) = {} bytes OK",
        KEM_CT_SIZE, NONCE_SIZE, HEADER_SIZE);

    let mut offset: u64 = HEADER_SIZE;
    let mut chunk_idx: u64 = 0;
    let mut total_plaintext: u64 = 0;
    let mut anomalies: Vec<String> = Vec::new();
    let mut last_good_offset: u64 = offset;
    let mut last_report_gb: u64 = 0;
    let mut found_eof = false;
    let mut found_manifest = false;

    loop {
        let mut len_bytes = [0u8; 4];
        match reader.read_exact(&mut len_bytes) {
            Ok(_) => {},
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                if !found_eof {
                    anomalies.push(format!(
                        "CRITICAL: File ends at offset {} without EOF marker. chunk_idx={}", offset, chunk_idx));
                }
                break;
            }
            Err(e) => { anomalies.push(format!("I/O error at offset {}: {}", offset, e)); break; }
        }

        let chunk_len = u32::from_be_bytes(len_bytes) as usize;

        // After EOF marker, expect manifest (small chunk, ~72 bytes)
        if found_eof {
            if chunk_len < 16 || chunk_len > 256 {
                anomalies.push(format!(
                    "Invalid manifest chunk length at offset {}: {} (expected ~72)", offset, chunk_len));
                break;
            }
            // Skip manifest data
            let mut skip_buf = vec![0u8; chunk_len];
            match reader.read_exact(&mut skip_buf) {
                Ok(_) => {
                    found_manifest = true;
                    offset += 4 + chunk_len as u64;
                    last_good_offset = offset;
                    eprintln!("[MANIFEST] Found at offset {}, wire_len={} bytes", offset - chunk_len as u64 - 4, chunk_len);
                }
                Err(_) => {
                    anomalies.push(format!("Manifest chunk truncated at offset {}", offset + 4));
                }
            }
            break;
        }

        // Validate data chunk length
        if chunk_len > MAX_ENCRYPTED_CHUNK {
            anomalies.push(format!(
                "CORRUPT CHUNK LENGTH at offset {}: chunk_len={} (max={}). chunk_idx={}. \
                 Raw: {}. Plaintext so far: {} bytes ({:.2} GB)",
                offset, chunk_len, MAX_ENCRYPTED_CHUNK, chunk_idx,
                hex_encode(&len_bytes), total_plaintext,
                total_plaintext as f64 / 1_073_741_824.0));
            break;
        }
        if chunk_len < 16 {
            anomalies.push(format!(
                "INVALID CHUNK LENGTH at offset {}: chunk_len={} (min=16). chunk_idx={}. Raw: {}",
                offset, chunk_len, chunk_idx, hex_encode(&len_bytes)));
            break;
        }

        offset += 4;

        let is_eof_marker = chunk_len == 16;
        let implied_plaintext = if chunk_len > 16 { chunk_len - 16 } else { 0 };

        // Verify chunk data exists
        let remaining = file_size.saturating_sub(offset);
        if (chunk_len as u64) > remaining {
            anomalies.push(format!(
                "TRUNCATED CHUNK at offset {}: need {} bytes, only {} remain. chunk_idx={}. \
                 Plaintext so far: {} bytes ({:.2} GB)",
                offset, chunk_len, remaining, chunk_idx,
                total_plaintext, total_plaintext as f64 / 1_073_741_824.0));
            break;
        }

        // Skip chunk data
        let mut remaining_to_skip = chunk_len;
        let mut skip_buf = vec![0u8; 65536.min(chunk_len)];
        while remaining_to_skip > 0 {
            let to_read = remaining_to_skip.min(skip_buf.len());
            reader.read_exact(&mut skip_buf[..to_read])
                .map_err(|e| format!("I/O error at offset {}: {}", offset, e))?;
            remaining_to_skip -= to_read;
        }

        last_good_offset = offset + chunk_len as u64;
        offset = last_good_offset;

        if is_eof_marker {
            eprintln!("[EOF MARKER] Found at chunk_idx={}, offset={}", chunk_idx, offset);
            found_eof = true;
            chunk_idx += 1;
            continue; // Try to read manifest next
        }

        total_plaintext += implied_plaintext as u64;

        // Progress every ~1GB
        let current_gb = total_plaintext / 1_073_741_824;
        if current_gb > last_report_gb {
            eprintln!("[SCAN {:>6.2} GB] chunk={:<8} offset={:<16}", 
                total_plaintext as f64 / 1_073_741_824.0, chunk_idx, offset);
            last_report_gb = current_gb;
        }

        chunk_idx += 1;
    }

    // Summary
    eprintln!();
    eprintln!("=== FORENSIC SCAN SUMMARY ===");
    eprintln!("  Total data chunks  : {}", if found_eof { chunk_idx - 1 } else { chunk_idx });
    eprintln!("  Implied plaintext  : {} bytes ({:.2} GB)", total_plaintext, total_plaintext as f64 / 1_073_741_824.0);
    eprintln!("  EOF marker         : {}", if found_eof { "[OK] Found" } else { "[ERR] MISSING" });
    eprintln!("  Integrity manifest : {}", if found_manifest { "[OK] Found" } else if found_eof { "[WARN] Missing (pre-manifest format?)" } else { "[ERR] N/A (no EOF)" });
    eprintln!("  Last valid offset  : {} / {} ({:.4}%)", 
        last_good_offset, file_size, (last_good_offset as f64 / file_size as f64) * 100.0);
    eprintln!("  Trailing bytes     : {}", file_size - last_good_offset);

    if anomalies.is_empty() {
        eprintln!();
        eprintln!("[OK] NO ANOMALIES — file structure is valid.");
    } else {
        eprintln!();
        eprintln!("[ERR] {} ANOMALIES:", anomalies.len());
        for (i, a) in anomalies.iter().enumerate() {
            eprintln!("  [{}] {}", i + 1, a);
        }
    }

    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}
