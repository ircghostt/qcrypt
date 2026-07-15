use std::process;
use std::io::Read;
use obfstr::obfstr;
use serde_json::Value;

pub fn resolve_ipfs(cid: &str, gateway_override: Option<&String>) -> String {
    if let Some(gw) = gateway_override {
        if gw.starts_with("http://") || gw.starts_with("https://") {
            let mut base = gw.clone();
            if !base.ends_with('/') {
                base.push('/');
            }
            if !base.ends_with("ipfs/") {
                base.push_str("ipfs/");
            }
            return format!("{}{}", base, cid);
        } else {
            // It's a tag, we need to fetch the live JSON
            let tag = gw.to_lowercase();
            let resp = ureq::get(obfstr!("https://ipfs.github.io/public-gateway-checker/gateways.json")).call().unwrap_or_else(|e| {  
                eprintln!("{} {}", obfstr!("Error fetching live IPFS gateway list:"), e); 
                process::exit(1); 
            });
            
            let json_str = resp.into_string().unwrap_or_else(|_| { 
                eprintln!("{}", obfstr!("Error reading IPFS gateway list response.")); 
                process::exit(1); 
            });
            
            let v: Value = serde_json::from_str(&json_str).unwrap_or_else(|_| { 
                eprintln!("{}", obfstr!("Error parsing live IPFS gateway JSON.")); 
                process::exit(1); 
            });
            
            // The JSON is an array of full gateway URLs (e.g. "https://ipfs.io")
            if let Some(arr) = v.as_array() {
                for item in arr {
                    if let Some(url_str) = item.as_str() {
                        if url_str.to_lowercase().contains(&tag) {
                            let mut base = url_str.to_string();
                            if !base.ends_with('/') {
                                base.push('/');
                            }
                            base.push_str("ipfs/");
                            return format!("{}{}", base, cid);
                        }
                    }
                }
            }
            eprintln!("{} '{}'", obfstr!("Error: Could not find any active public gateway matching the tag:"), tag);
            process::exit(1);
        }
    } else {
        // Default reliable gateway
        format!("https://ipfs.io/ipfs/{}", cid)
    }
}

pub fn upload_to_ipfs(data: &[u8], api_token: &str) -> Result<String, String> {
    stream_to_ipfs(data, api_token)
}

pub fn stream_to_ipfs(reader: impl Read, api_token: &str) -> Result<String, String> {
    let api_url = "https://api.pinata.cloud/pinning/pinFileToIPFS";
    let boundary = "------------------------Boundary123456789";
    let header = format!("--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"payload\"\r\nContent-Type: application/octet-stream\r\n\r\n", boundary);
    let footer = format!("\r\n--{}--\r\n", boundary);
    
    let payload_reader = std::io::Cursor::new(header.into_bytes())
        .chain(reader)
        .chain(std::io::Cursor::new(footer.into_bytes()));
        
    let resp = ureq::post(api_url)
        .set("Authorization", &format!("Bearer {}", api_token))
        .set("Content-Type", &format!("multipart/form-data; boundary={}", boundary))
        .send(payload_reader)
        .map_err(|e| e.to_string())?;
        
    let json_str = resp.into_string().map_err(|_| "Failed to read response")?;
    let v: Value = serde_json::from_str(&json_str).map_err(|_| "Failed to parse JSON")?;
    
    if let Some(hash) = v.get("IpfsHash").and_then(|h| h.as_str()) {
        Ok(hash.to_string())
    } else {
        Err("Response missing IpfsHash".to_string())
    }
}
