pub fn yubikey_challenge(challenge: &[u8]) -> Result<Vec<u8>, String> {
    use yubikey_hmac_otp::{Yubico};
    use yubikey_hmac_otp::config::{Config, Slot, Mode};
    use std::ops::Deref;
    
    let mut yubi = Yubico::new();
    let device = yubi.find_yubikey().map_err(|_| "Error: No YubiKey detected. Please insert your YubiKey.")?;
    
    let config = Config::new_from(device)
        .set_mode(Mode::Sha1)
        .set_slot(Slot::Slot2);
        
    let hmac_result = yubi.challenge_response_hmac(challenge, config).map_err(|e| format!("Error: YubiKey Challenge failed: {:?}", e))?;
    Ok(hmac_result.deref().to_vec())
}

pub fn generate_hmac_secret(pass: Option<String>, tgt_loc: Option<std::path::PathBuf>, direct: bool, direct_touch: bool) {
    let pass1 = if let Some(p) = pass {
        p
    } else {
        let p1 = rpassword::prompt_password(obfstr::obfstr!("Enter passphrase for HMAC-SHA1 generation (min 16 chars): ")).unwrap_or_else(|_| { eprintln!("Error reading passphrase"); std::process::exit(1); });
        let p2 = rpassword::prompt_password(obfstr::obfstr!("Confirm passphrase: ")).unwrap_or_else(|_| { eprintln!("Error reading passphrase"); std::process::exit(1); });
        if p1 != p2 {
            eprintln!("{}", obfstr::obfstr!("Passphrases do not match. Aborting."));
            std::process::exit(1);
        }
        p1
    };
    
    if pass1.len() < 16 {
        eprintln!("{}", obfstr::obfstr!("Passphrase rejected: Must be at least 16 characters."));
        std::process::exit(1);
    }
    
    let static_salt = b"qcrypt_yubi_salt";
    let mut out = [0u8; 20];
    argon2::Argon2::default().hash_password_into(pass1.as_bytes(), static_salt, &mut out).expect("Argon2id derivation failed");
    
    use std::fmt::Write;
    let mut hex_out = String::with_capacity(40);
    for byte in &out {
        write!(&mut hex_out, "{:02x}", byte).unwrap();
    }
    
    if direct {
        println!("Attempting direct injection to YubiKey...");
        use yubikey_hmac_otp::Yubico;
        use yubikey_hmac_otp::config::{Config, Command};
        use yubikey_hmac_otp::configure::DeviceModeConfig;
        use yubikey_hmac_otp::hmacmode::HmacKey;

        let mut yubi = Yubico::new();
        let device = yubi.find_yubikey().unwrap_or_else(|_| {
            eprintln!("Error: YubiKey not detected. Aborting injection. Zero-disk policy enforced.");
            std::process::exit(1);
        });

        let config = Config::new_from(device)
            .set_command(Command::Configuration2);

        let hmac_key = HmacKey::from_slice(&out);
        let mut device_config = DeviceModeConfig::default();

        let variable_size = false; // We use a fixed 20-byte secret
        device_config.challenge_response_hmac(&hmac_key, variable_size, direct_touch);

        yubi.write_config(config, &mut device_config).unwrap_or_else(|e| {
            eprintln!("Error: Failed to write to YubiKey: {:?}", e);
            std::process::exit(1);
        });
        
        println!("Secret Successfully Injected into YubiKey Slot 2! (Zero-Disk Provisioning)");
    } else {
        let out_file = tgt_loc.unwrap_or_else(|| std::path::PathBuf::from("hmac_sha1_key.hex"));
        std::fs::write(&out_file, &hex_out).unwrap_or_else(|_| { eprintln!("Error writing to {:?}", out_file); std::process::exit(1); });
        
        println!("Deterministic HMAC-SHA1 Secret (40-char Hex):");
        println!("{}", hex_out);
        println!("\nSaved to: {:?}", out_file);
        println!("Use this file to program your YubiKeys via ykman.");
    }
}

pub fn derive_eth_key(passphrase: Option<String>, use_yubikey: bool, salt: &str) -> Result<secp256k1::SecretKey, String> {
    let mut key_material = [0u8; 32];
    
    let mut argon_salt = salt.as_bytes().to_vec();
    if argon_salt.len() < 8 {
        argon_salt.resize(8, 0); // Pad with zeros to meet 8-byte minimum
    }
    
    if use_yubikey {
        // YubiKey Mode: Challenge = salt
        let mut challenge = salt.as_bytes().to_vec();
        if challenge.len() > 64 {
            challenge.truncate(64);
        }
        let hmac_response = yubikey_challenge(&challenge)?;
        
        // Hash the HMAC response using Argon2id to get exactly 32 bytes
        argon2::Argon2::default().hash_password_into(&hmac_response, &argon_salt, &mut key_material)
            .map_err(|e| format!("Argon2id derivation failed: {}", e))?;
    } else {
        // Passphrase Mode
        let pass = passphrase.ok_or_else(|| "Passphrase required for deterministic derivation".to_string())?;
        if pass.len() < 16 {
            return Err("Passphrase rejected: Must be at least 16 characters.".to_string());
        }
        
        argon2::Argon2::default().hash_password_into(pass.as_bytes(), &argon_salt, &mut key_material)
            .map_err(|e| format!("Argon2id derivation failed: {}", e))?;
    }
    
    secp256k1::SecretKey::from_byte_array(key_material).map_err(|e| format!("Invalid scalar generated: {}", e))
}
