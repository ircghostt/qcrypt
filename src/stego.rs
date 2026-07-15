use std::path::Path;

/// Injects a binary payload into a PNG carrier using Stride-Dispersed LSB Steganography.
pub fn inject_lsb(carrier_path: &Path, output_path: &Path, payload: &[u8]) -> Result<(), String> {
    if !carrier_path.extension().map_or(false, |ext| ext.eq_ignore_ascii_case("png") || ext.eq_ignore_ascii_case("bmp")) {
        return Err("Carrier must be a lossless format (.png or .bmp) to prevent key corruption.".into());
    }

    let img = image::open(carrier_path).map_err(|e| format!("Failed to open carrier: {}", e))?;
    let mut img_rgba = img.to_rgba8();
    
    let (width, height) = img_rgba.dimensions();
    let total_pixels = (width as u64) * (height as u64);
    let total_channels = total_pixels * 3; // Using R, G, B

    let payload_bits_len = (payload.len() as u64) * 8;
    let header_bits_len = 64u64; // 8 bytes for size
    
    let header_stride = 13u64; // Fixed prime-ish stride for the 64-bit header to avoid contiguous block
    let channels_used_by_header = header_bits_len * header_stride;

    if total_channels <= channels_used_by_header {
        return Err("Carrier image is microscopically too small even for the stego header.".into());
    }

    let remaining_channels = total_channels - channels_used_by_header;
    if remaining_channels < payload_bits_len {
        return Err("Carrier image capacity exceeded. Use a higher resolution photo.".into());
    }

    let payload_stride = remaining_channels / payload_bits_len;
    if payload_stride < 1 {
        return Err("Payload stride < 1. Carrier too small.".into());
    }

    let payload_len_bytes = (payload.len() as u64).to_le_bytes();
    
    // Create a bit iterator for header
    let mut header_bits = Vec::with_capacity(64);
    for byte in payload_len_bytes {
        for i in 0..8 {
            header_bits.push((byte >> i) & 1);
        }
    }

    // Create a bit iterator for payload
    let mut payload_bits = Vec::with_capacity(payload.len() * 8);
    for byte in payload {
        for i in 0..8 {
            payload_bits.push((byte >> i) & 1);
        }
    }

    let mut current_channel: u64 = 0;
    let mut header_idx = 0;
    let mut payload_idx = 0;

    // Mutate the image
    for (_, _, pixel) in img_rgba.enumerate_pixels_mut() {
        for c in 0..3 { // R, G, B only, skip Alpha to avoid transparency weirdness
            if current_channel < channels_used_by_header {
                // Header phase
                if current_channel % header_stride == 0 && header_idx < 64 {
                    let bit = header_bits[header_idx];
                    pixel[c] = (pixel[c] & 0xFE) | bit;
                    header_idx += 1;
                }
            } else if payload_idx < payload_bits.len() {
                // Payload phase
                let shifted_channel = current_channel - channels_used_by_header;
                if shifted_channel % payload_stride == 0 {
                    let bit = payload_bits[payload_idx];
                    pixel[c] = (pixel[c] & 0xFE) | bit;
                    payload_idx += 1;
                }
            }
            current_channel += 1;
        }
    }

    img_rgba.save(output_path).map_err(|e| format!("Failed to save stego image: {}", e))?;
    Ok(())
}

/// Extracts a binary payload from a Stride-Dispersed LSB PNG carrier from the filesystem.
pub fn extract_lsb(carrier_path: &Path) -> Result<Vec<u8>, String> {
    let img = image::open(carrier_path).map_err(|e| format!("Failed to open stego carrier: {}", e))?;
    extract_lsb_from_image(img)
}

/// Extracts a binary payload from a Stride-Dispersed LSB PNG carrier stored in a raw byte slice (in-memory).
pub fn extract_lsb_from_memory(image_data: &[u8]) -> Result<Vec<u8>, String> {
    let img = image::load_from_memory(image_data).map_err(|e| format!("Failed to decode stego carrier from memory: {}", e))?;
    extract_lsb_from_image(img)
}

fn extract_lsb_from_image(img: image::DynamicImage) -> Result<Vec<u8>, String> {
    let img_rgba = img.to_rgba8();
    
    let (width, height) = img_rgba.dimensions();
    let total_pixels = (width as u64) * (height as u64);
    let total_channels = total_pixels * 3;

    let header_bits_len = 64u64;
    let header_stride = 13u64;
    let channels_used_by_header = header_bits_len * header_stride;

    if total_channels <= channels_used_by_header {
        return Err("Invalid stego carrier: Too small to contain header.".into());
    }

    let mut current_channel: u64 = 0;
    
    let mut header_bits = Vec::with_capacity(64);
    let mut payload_bits = Vec::new(); // Will size after reading header
    
    let mut payload_len: u64 = 0;
    let mut payload_stride: u64 = 0;
    let mut payload_target_bits: usize = 0;

    for (_, _, pixel) in img_rgba.enumerate_pixels() {
        for c in 0..3 {
            if current_channel < channels_used_by_header {
                if current_channel % header_stride == 0 && header_bits.len() < 64 {
                    header_bits.push(pixel[c] & 1);
                    if header_bits.len() == 64 {
                        // Reconstruct header
                        let mut len_bytes = [0u8; 8];
                        for i in 0..8 {
                            let mut b = 0u8;
                            for j in 0..8 {
                                b |= header_bits[i * 8 + j] << j;
                            }
                            len_bytes[i] = b;
                        }
                        payload_len = u64::from_le_bytes(len_bytes);
                        
                        let remaining_channels = total_channels - channels_used_by_header;
                        let payload_bits_len = payload_len * 8;
                        
                        if payload_bits_len == 0 || remaining_channels < payload_bits_len {
                            return Err("Stego extraction failed: Invalid payload size in header (corrupted or not a stego file).".into());
                        }
                        
                        payload_stride = remaining_channels / payload_bits_len;
                        payload_target_bits = payload_bits_len as usize;
                        payload_bits.reserve(payload_target_bits);
                    }
                }
            } else if payload_bits.len() < payload_target_bits {
                let shifted_channel = current_channel - channels_used_by_header;
                if shifted_channel % payload_stride == 0 {
                    payload_bits.push(pixel[c] & 1);
                }
            }
            current_channel += 1;
            
            if header_bits.len() == 64 && payload_bits.len() == payload_target_bits {
                break;
            }
        }
        if header_bits.len() == 64 && payload_bits.len() == payload_target_bits {
            break;
        }
    }

    if payload_bits.len() < payload_target_bits {
        return Err("Stego extraction failed: Reached EOF before fully extracting payload.".into());
    }

    let mut payload = Vec::with_capacity(payload_len as usize);
    for i in 0..(payload_len as usize) {
        let mut b = 0u8;
        for j in 0..8 {
            b |= payload_bits[i * 8 + j] << j;
        }
        payload.push(b);
    }

    Ok(payload)
}
