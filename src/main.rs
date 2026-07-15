pub mod hybrid;
pub mod cli;
mod ipfs;
pub mod forensic;
pub mod arweave;
pub mod gui;
mod stego;
mod yubikey;

fn resolve_eth_key(useslot2: bool, salt_opt: Option<&str>, eth_key_opt: Option<&str>) -> Option<String> {
    if useslot2 {
        let salt = salt_opt.unwrap_or_else(|| {
            eprintln!("Error: --yubikey_ethkey_salt is required when --yubikey_ethkey_useslot2 is set.");
            std::process::exit(1);
        });
        match crate::yubikey::derive_eth_key(None, true, salt) {
            Ok(sk) => Some(format!("0x{}", sk.display_secret())),
            Err(e) => {
                eprintln!("Error deriving ETH key from YubiKey: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        eth_key_opt.map(|s| s.to_string())
    }
}

use clap::Parser;
use std::fs;
use cli::{Cli, Commands};


fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { pass, nopemhead, stego, yubikey, yubikey_and_pass } => {
            let auth_mode = if yubikey_and_pass {
                hybrid::AuthMode::HardwareAndPassphrase
            } else if yubikey {
                hybrid::AuthMode::HardwareOnly
            } else {
                hybrid::AuthMode::Passphrase
            };
            
            let pass1 = if auth_mode == hybrid::AuthMode::HardwareOnly {
                String::new()
            } else if let Some(p) = pass {
                p
            } else {
                let p1 = rpassword::prompt_password(obfstr::obfstr!("Enter passphrase to lock private key (min 16 chars): ")).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: Failed to read passphrase")); std::process::exit(1); });
                let p2 = rpassword::prompt_password(obfstr::obfstr!("Confirm passphrase: ")).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: Failed to read passphrase")); std::process::exit(1); });
                if p1 != p2 {
                    eprintln!("{}", obfstr::obfstr!("Passphrases do not match. Aborting."));
                    std::process::exit(1);
                }
                p1
            };
            
            if auth_mode != hybrid::AuthMode::HardwareOnly && pass1.len() < 16 {
                eprintln!("{}", obfstr::obfstr!("Passphrase rejected: Must be at least 16 characters to mathematically defeat cloud GPU clusters. Aborting."));
                std::process::exit(1);
            }
            
            if auth_mode != hybrid::AuthMode::Passphrase {
                println!("{}", obfstr::obfstr!("Please touch your YubiKey..."));
            }
            
            let zero_pass = zeroize::Zeroizing::new(pass1);
            
            let (priv_pem, pub_pem) = hybrid::generate_keys(&zero_pass, nopemhead, &auth_mode);
            if let Some(api_token) = &cli.ipfs_pinata_jwt {
                let priv_cid = ipfs::upload_to_ipfs(priv_pem.as_bytes(), api_token).unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("IPFS Upload Error (priv_key):"), e); std::process::exit(1); });
                let pub_cid = ipfs::upload_to_ipfs(pub_pem.as_bytes(), api_token).unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("IPFS Upload Error (pub_key):"), e); std::process::exit(1); });
                
                fs::write(obfstr::obfstr!("priv_key.cid"), priv_cid).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: Failed to write priv_key.cid")); std::process::exit(1); });
                fs::write(obfstr::obfstr!("pub_key.cid"), pub_cid).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: Failed to write pub_key.cid")); std::process::exit(1); });
                println!("{}", obfstr::obfstr!("Keys generated and injected to IPFS successfully. (.cid files saved locally)"));
            } else if let Some(eth_key_str) = resolve_eth_key(cli.yubikey_ethkey_useslot2, cli.yubikey_ethkey_salt.as_deref(), cli.arweave_eth_key.as_deref()) {
                let eth_key = &eth_key_str;
                let priv_txid = arweave::upload_to_irys(priv_pem.as_bytes(), eth_key).unwrap_or_else(|e| { eprintln!("Arweave Upload Error (priv_key): {}", e); std::process::exit(1); });
                let pub_txid = arweave::upload_to_irys(pub_pem.as_bytes(), eth_key).unwrap_or_else(|e| { eprintln!("Arweave Upload Error (pub_key): {}", e); std::process::exit(1); });
                
                let clean_priv_txid = if priv_txid.contains("\"id\":\"") { priv_txid.split("\"id\":\"").nth(1).unwrap_or(&priv_txid).split("\"").next().unwrap_or(&priv_txid).to_string() } else { priv_txid };
                let clean_pub_txid = if pub_txid.contains("\"id\":\"") { pub_txid.split("\"id\":\"").nth(1).unwrap_or(&pub_txid).split("\"").next().unwrap_or(&pub_txid).to_string() } else { pub_txid };

                fs::write("priv_key.txid", &clean_priv_txid).unwrap_or_else(|_| { eprintln!("Error: Failed to write priv_key.txid"); std::process::exit(1); });
                fs::write("pub_key.txid", &clean_pub_txid).unwrap_or_else(|_| { eprintln!("Error: Failed to write pub_key.txid"); std::process::exit(1); });
                println!("Keys generated and injected to Arweave successfully. (.txid files saved locally)");
            } else {
                if let Some(carrier) = stego {
                    stego::inject_lsb(&carrier, &std::path::PathBuf::from("priv_key_stego.png"), priv_pem.as_bytes())
                        .unwrap_or_else(|e| { eprintln!("Stego Injection Error: {}", e); std::process::exit(1); });
                    fs::write(obfstr::obfstr!("pub_key.pem"), pub_pem).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: Failed to write public key.")); std::process::exit(1); });
                    println!("Keys generated successfully. Private key hidden in priv_key_stego.png");
                } else {
                    fs::write(obfstr::obfstr!("priv_key.pem"), priv_pem).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: Failed to write private key.")); std::process::exit(1); });
                    fs::write(obfstr::obfstr!("pub_key.pem"), pub_pem).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: Failed to write public key.")); std::process::exit(1); });
                    println!("{}", obfstr::obfstr!("Keys generated successfully in current directory."));
                }
            }
        }
        Commands::KeygenEth { tgt_loc, deterministic, salt, passphrase, yubikey } => {
            let out_file = tgt_loc.unwrap_or_else(|| std::path::PathBuf::from("ethereum.key"));
            
            if deterministic {
                let salt_val = salt.unwrap_or_else(|| { eprintln!("Error: --salt is required when --deterministic is set"); std::process::exit(1); });
                match crate::yubikey::derive_eth_key(passphrase, yubikey, &salt_val) {
                    Ok(secret_key) => {
                        let hex_key = format!("0x{}", secret_key.display_secret());
                        fs::write(&out_file, &hex_key).unwrap_or_else(|_| { eprintln!("Error: Failed to write {:?}", out_file); std::process::exit(1); });
                        println!("Deterministic Ethereum Secp256k1 Private Key successfully generated and saved to: {:?}", out_file);
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                let secp = secp256k1::Secp256k1::new();
                let (secret_key, _public_key) = secp.generate_keypair(&mut secp256k1::rand::rng());
                let hex_key = format!("0x{}", secret_key.display_secret());
                fs::write(&out_file, &hex_key).unwrap_or_else(|_| { eprintln!("Error: Failed to write {:?}", out_file); std::process::exit(1); });
                println!("Random Ethereum Secp256k1 Private Key successfully generated and saved to: {:?}", out_file);
            }
        }
        Commands::TestIrys { file } => {
            let data = fs::read(&file).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: Failed to read file")); std::process::exit(1); });
            let eth_key_str = resolve_eth_key(cli.yubikey_ethkey_useslot2, cli.yubikey_ethkey_salt.as_deref(), cli.arweave_eth_key.as_deref()).unwrap_or_else(|| {
                eprintln!("{}", obfstr::obfstr!("Error: --arweave_eth_key or --yubikey_ethkey_useslot2 is required for test-irys"));
                std::process::exit(1);
            });
            let eth_key = &eth_key_str;
            println!("Deep Hashing and Signing {} for Irys upload...", file);
            match arweave::upload_to_irys(&data, &eth_key) {
                Ok(body) => println!("Upload Success! Irys Node Response: {}", body),
                Err(e) => eprintln!("Upload Failed: {}", e),
            }
        }
        Commands::Encrypt { file, src_net, src_loc, src_ipfs, pubkey_net, pubkey_loc, pubkey_ipfs, tgt_loc } => {
            let src_loc = src_loc.or(file);
            let (pub_key_pem, key_name) = if let Some(url) = pubkey_net {
                let resp = ureq::get(&url).call().unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("Error fetching public key from network:"), e); std::process::exit(1); });
                (resp.into_string().unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error reading public key string")); std::process::exit(1); }), url)
            } else if let Some(cid) = pubkey_ipfs {
                let url = ipfs::resolve_ipfs(&cid, cli.ipfs_gateway.as_ref());
                let resp = ureq::get(&url).call().unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("Error fetching public key from IPFS:"), e); std::process::exit(1); });
                (resp.into_string().unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error reading public key string")); std::process::exit(1); }), format!("IPFS:{}", cid))
            } else if let Some(path) = pubkey_loc {
                let p_str = path.to_string_lossy().to_string();
                (fs::read_to_string(&path).unwrap_or_else(|_| { eprintln!("{} {:?}", obfstr::obfstr!("Error: public key not found at"), path); std::process::exit(1); }), p_str)
            } else {
                (fs::read_to_string(obfstr::obfstr!("pub_key.pem")).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: pub_key.pem not found in current directory. Generate keys first.")); std::process::exit(1); }), obfstr::obfstr!("pub_key.pem").to_string())
            };
            
            let (input, out_file): (Box<dyn std::io::Read + Send>, std::path::PathBuf) = if let Some(url) = src_net {
                let resp = ureq::get(&url).call().unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("Error fetching payload from network:"), e); std::process::exit(1); });
                let default_name = url.split('/').last().unwrap_or("payload").to_string();
                let f_out = tgt_loc.clone().unwrap_or_else(|| std::path::PathBuf::from(format!("{}.enc", default_name)));
                (Box::new(resp.into_reader()), f_out)
            } else if let Some(cid) = src_ipfs {
                let url = ipfs::resolve_ipfs(&cid, cli.ipfs_gateway.as_ref());
                let resp = ureq::get(&url).call().unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("Error fetching payload from IPFS:"), e); std::process::exit(1); });
                let f_out = tgt_loc.clone().unwrap_or_else(|| std::path::PathBuf::from(format!("{}.enc", cid)));
                (Box::new(resp.into_reader()), f_out)
            } else if let Some(path) = src_loc {
                let f = fs::File::open(&path).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: Failed to open input file. Please check the path.")); std::process::exit(1); });
                let f_out = tgt_loc.clone().unwrap_or_else(|| {
                    let mut out_os = path.clone().into_os_string();
                    out_os.push(obfstr::obfstr!(".enc"));
                    std::path::PathBuf::from(out_os)
                });
                (Box::new(f), f_out)
            } else {
                eprintln!("{}", obfstr::obfstr!("Error: Must provide --src_net, --src_loc, or --src_ipfs"));
                std::process::exit(1);
            };
            
            let zero_pub_key = zeroize::Zeroizing::new(pub_key_pem);
            
            if let Some(api_token) = &cli.ipfs_pinata_jwt {
                let buffer = std::io::Cursor::new(Vec::new());
                let mut buffer = hybrid::encrypt_stream(input, buffer, &zero_pub_key).unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("Encryption Error:"), e); std::process::exit(1); });
                buffer.set_position(0);
                
                let cid = ipfs::stream_to_ipfs(buffer, api_token).unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("IPFS Upload Error:"), e); std::process::exit(1); });
                
                let out_file = tgt_loc.clone().unwrap_or_else(|| std::path::PathBuf::from("payload.cid"));
                fs::write(&out_file, &cid).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: Failed to write .cid file.")); std::process::exit(1); });
                println!("{} {:?} {} {}", obfstr::obfstr!("File encrypted & uploaded successfully to IPFS. CID saved to:"), out_file, obfstr::obfstr!("using:"), key_name);
            } else if let Some(eth_key_str) = resolve_eth_key(cli.yubikey_ethkey_useslot2, cli.yubikey_ethkey_salt.as_deref(), cli.arweave_eth_key.as_deref()) {
                  let eth_key = &eth_key_str;
                  let buffer = std::io::Cursor::new(Vec::new());
                  let buffer = hybrid::encrypt_stream(input, buffer, &zero_pub_key).unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("Encryption Error:"), e); std::process::exit(1); });
                  let data = buffer.into_inner();
                  
                  if data.len() > 100 * 1024 && !arweave::has_irys_balance(eth_key) {
                      eprintln!("Error: Encrypted payload size is {} bytes. Irys free tier is limited to < 100KB, and your 'ethereum.key' wallet has no prepaid balance. Aborting upload.", data.len());
                      std::process::exit(1);
                  }
                  
                  println!("Deep Hashing and Uploading Ciphertext to Irys/Arweave...");
                  let txid = arweave::upload_to_irys(&data, eth_key).unwrap_or_else(|e| { eprintln!("Arweave Upload Error: {}", e); std::process::exit(1); });
                  
                  // Irys usually returns JSON like {"id": "..."}. Let's try to extract the ID manually or just write the whole response if it fails.
                  let clean_txid = if txid.contains("\"id\":\"") {
                      txid.split("\"id\":\"").nth(1).unwrap_or(&txid).split("\"").next().unwrap_or(&txid).to_string()
                  } else {
                      txid.clone()
                  };
                  
                  let out_file = tgt_loc.clone().unwrap_or_else(|| std::path::PathBuf::from("payload.txid"));
                  fs::write(&out_file, &clean_txid).unwrap_or_else(|_| { eprintln!("Error: Failed to write .txid file."); std::process::exit(1); });
                  println!("File encrypted & uploaded successfully to Irys/Arweave. TxID saved to: {:?} using: {}", out_file, key_name);
            } else {
                let output = fs::File::create(&out_file).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: Failed to create output archive.")); std::process::exit(1); });
                hybrid::encrypt_stream(input, output.try_clone().unwrap(), &zero_pub_key).unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("Encryption Error:"), e); std::process::exit(1); });
                output.sync_all().unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: Failed to sync encrypted file to disk.")); std::process::exit(1); });
                println!("{} {:?} {} {}", obfstr::obfstr!("File encrypted successfully to:"), out_file, obfstr::obfstr!("using:"), key_name);
            }
        }
        Commands::Decrypt { file, src_net, src_loc, src_ipfs, privkey_net, privkey_loc, privkey_ipfs, tgt_loc, pass, stego, yubikey, yubikey_and_pass } => {
            let auth_mode = if yubikey_and_pass {
                hybrid::AuthMode::HardwareAndPassphrase
            } else if yubikey {
                hybrid::AuthMode::HardwareOnly
            } else {
                hybrid::AuthMode::Passphrase
            };
            
            let src_loc = src_loc.or(file);
            let (priv_key_pem, key_name) = if let Some(url) = privkey_net {
                let mut reader = ureq::get(&url).call().unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("Error fetching private key from network:"), e); std::process::exit(1); }).into_reader();
                let mut bytes = Vec::new();
                std::io::Read::read_to_end(&mut reader, &mut bytes).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error reading network stream")); std::process::exit(1); });
                if stego {
                    let extracted = stego::extract_lsb_from_memory(&bytes).unwrap_or_else(|e| { eprintln!("Stego Extraction Error: {}", e); std::process::exit(1); });
                    (String::from_utf8_lossy(&extracted).into_owned(), url)
                } else {
                    (String::from_utf8_lossy(&bytes).into_owned(), url)
                }
            } else if let Some(cid) = privkey_ipfs {
                let url = ipfs::resolve_ipfs(&cid, cli.ipfs_gateway.as_ref());
                let mut reader = ureq::get(&url).call().unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("Error fetching private key from IPFS:"), e); std::process::exit(1); }).into_reader();
                let mut bytes = Vec::new();
                std::io::Read::read_to_end(&mut reader, &mut bytes).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error reading IPFS stream")); std::process::exit(1); });
                let name = format!("IPFS:{}", cid);
                if stego {
                    let extracted = stego::extract_lsb_from_memory(&bytes).unwrap_or_else(|e| { eprintln!("Stego Extraction Error: {}", e); std::process::exit(1); });
                    (String::from_utf8_lossy(&extracted).into_owned(), name)
                } else {
                    (String::from_utf8_lossy(&bytes).into_owned(), name)
                }
            } else {
                let path = privkey_loc.unwrap_or_else(|| {
                    if stego { std::path::PathBuf::from("priv_key_stego.png") } else { std::path::PathBuf::from("priv_key.pem") }
                });
                let p_str = path.to_string_lossy().to_string();
                if stego {
                    let extracted = stego::extract_lsb(&path).unwrap_or_else(|e| { eprintln!("Stego Extraction Error: {}", e); std::process::exit(1); });
                    (String::from_utf8_lossy(&extracted).into_owned(), p_str)
                } else {
                    (fs::read_to_string(&path).unwrap_or_else(|_| { eprintln!("{} {:?}", obfstr::obfstr!("Error: private key not found at"), path); std::process::exit(1); }), p_str)
                }
            };
            
            let pass_input = if auth_mode == hybrid::AuthMode::HardwareOnly {
                String::new()
            } else {
                pass.unwrap_or_else(|| {
                    rpassword::prompt_password(obfstr::obfstr!("Enter decryption passphrase: ")).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: Failed to read passphrase")); std::process::exit(1); })
                })
            };
            
            if auth_mode != hybrid::AuthMode::Passphrase {
                println!("{}", obfstr::obfstr!("Please touch your YubiKey..."));
            }
            
            let zero_pass = zeroize::Zeroizing::new(pass_input);
            
            let (input, out_file): (Box<dyn std::io::Read + Send>, std::path::PathBuf) = if let Some(url) = src_net {
                let resp = ureq::get(&url).call().unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("Error fetching payload from network:"), e); std::process::exit(1); });
                let default_name = url.split('/').last().unwrap_or("payload.enc").to_string();
                let stripped_name = if default_name.ends_with(".enc") { default_name.strip_suffix(".enc").unwrap().to_string() } else { format!("{}.dec", default_name) };
                let f_out = tgt_loc.unwrap_or_else(|| std::path::PathBuf::from(stripped_name));
                (Box::new(resp.into_reader()), f_out)
            } else if let Some(cid) = src_ipfs {
                let url = ipfs::resolve_ipfs(&cid, cli.ipfs_gateway.as_ref());
                let resp = ureq::get(&url).call().unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("Error fetching payload from IPFS:"), e); std::process::exit(1); });
                let f_out = tgt_loc.unwrap_or_else(|| std::path::PathBuf::from(format!("{}.dec", cid)));
                (Box::new(resp.into_reader()), f_out)
            } else if let Some(path) = src_loc {
                let f = fs::File::open(&path).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: Failed to open encrypted archive. Please check the path.")); std::process::exit(1); });
                let f_out = tgt_loc.unwrap_or_else(|| path.with_extension(""));
                (Box::new(f), f_out)
            } else {
                eprintln!("{}", obfstr::obfstr!("Error: Must provide --src_net, --src_loc, or --src_ipfs"));
                std::process::exit(1);
            };
            
            let output = fs::File::create(&out_file).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: Failed to create decrypted file.")); std::process::exit(1); });
            
            hybrid::decrypt_stream(input, output.try_clone().unwrap(), &priv_key_pem, &zero_pass, &auth_mode).unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("Decryption Error:"), e); std::process::exit(1); });
            
            output.sync_all().unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: Failed to sync decrypted file to disk.")); std::process::exit(1); });
            
            let _zero_priv_key = zeroize::Zeroizing::new(priv_key_pem);
            
            println!("{} {:?} {} {}", obfstr::obfstr!("File decrypted successfully to:"), out_file, obfstr::obfstr!("using:"), key_name);
        }
        Commands::Forensic { file, keygen_pub, privkey_net, privkey_loc, privkey_ipfs, tgt_loc, pass, yubikey, yubikey_and_pass, stego, nopemhead } => {
            if keygen_pub {
                let auth_mode = if yubikey_and_pass {
                    hybrid::AuthMode::HardwareAndPassphrase
                } else if yubikey {
                    hybrid::AuthMode::HardwareOnly
                } else {
                    hybrid::AuthMode::Passphrase
                };
                
                let (priv_key_pem, key_name) = if let Some(url) = privkey_net {
                    let mut reader = ureq::get(&url).call().unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("Error fetching private key from network:"), e); std::process::exit(1); }).into_reader();
                    let mut bytes = Vec::new();
                    std::io::Read::read_to_end(&mut reader, &mut bytes).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error reading network stream")); std::process::exit(1); });
                    if stego {
                        let extracted = stego::extract_lsb_from_memory(&bytes).unwrap_or_else(|e| { eprintln!("Stego Extraction Error: {}", e); std::process::exit(1); });
                        (String::from_utf8_lossy(&extracted).into_owned(), url)
                    } else {
                        (String::from_utf8_lossy(&bytes).into_owned(), url)
                    }
                } else if let Some(cid) = privkey_ipfs {
                    let url = ipfs::resolve_ipfs(&cid, cli.ipfs_gateway.as_ref());
                    let mut reader = ureq::get(&url).call().unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("Error fetching private key from IPFS:"), e); std::process::exit(1); }).into_reader();
                    let mut bytes = Vec::new();
                    std::io::Read::read_to_end(&mut reader, &mut bytes).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error reading IPFS stream")); std::process::exit(1); });
                    let name = format!("IPFS:{}", cid);
                    if stego {
                        let extracted = stego::extract_lsb_from_memory(&bytes).unwrap_or_else(|e| { eprintln!("Stego Extraction Error: {}", e); std::process::exit(1); });
                        (String::from_utf8_lossy(&extracted).into_owned(), name)
                    } else {
                        (String::from_utf8_lossy(&bytes).into_owned(), name)
                    }
                } else {
                    let path = privkey_loc.unwrap_or_else(|| {
                        if stego { std::path::PathBuf::from("priv_key_stego.png") } else { std::path::PathBuf::from("priv_key.pem") }
                    });
                    let p_str = path.to_string_lossy().to_string();
                    if stego {
                        let extracted = stego::extract_lsb(&path).unwrap_or_else(|e| { eprintln!("Stego Extraction Error: {}", e); std::process::exit(1); });
                        (String::from_utf8_lossy(&extracted).into_owned(), p_str)
                    } else {
                        (fs::read_to_string(&path).unwrap_or_else(|_| { eprintln!("{} {:?}", obfstr::obfstr!("Error: private key not found at"), path); std::process::exit(1); }), p_str)
                    }
                };
                
                let pass_input = if auth_mode == hybrid::AuthMode::HardwareOnly {
                    String::new()
                } else {
                    pass.unwrap_or_else(|| {
                        rpassword::prompt_password(obfstr::obfstr!("Enter unlocking passphrase: ")).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: Failed to read passphrase")); std::process::exit(1); })
                    })
                };
                
                if auth_mode != hybrid::AuthMode::Passphrase {
                    println!("{}", obfstr::obfstr!("Please touch your YubiKey..."));
                }
                
                let zero_pass = zeroize::Zeroizing::new(pass_input);
                
                let pub_pem = hybrid::recover_public_key(&priv_key_pem, &zero_pass, &auth_mode, nopemhead)
                    .unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("Public Key Recovery Error:"), e); std::process::exit(1); });
                    
                let out_file = tgt_loc.unwrap_or_else(|| std::path::PathBuf::from("pub_key.pem"));
                fs::write(&out_file, pub_pem).unwrap_or_else(|_| { eprintln!("{}", obfstr::obfstr!("Error: Failed to write regenerated public key.")); std::process::exit(1); });
                
                println!("{} {:?} {} {}", obfstr::obfstr!("Public key successfully regenerated to:"), out_file, obfstr::obfstr!("from private key:"), key_name);
            } else {
                if let Some(archive_path) = file {
                    forensic::forensic_scan(&archive_path).unwrap_or_else(|e| { eprintln!("{} {}", obfstr::obfstr!("Forensic Error:"), e); std::process::exit(1); });
                } else {
                    eprintln!("{}", obfstr::obfstr!("Error: You must provide an encrypted file for forensic scan, or use --keygen_pub for public key regeneration."));
                    std::process::exit(1);
                }
            }
        }
        Commands::Gui => {
            gui::run_gui();
        }
        Commands::Stego { inject, extract, tgt_loc, src_loc, privkey_loc } => {
            if inject {
                let key_path = privkey_loc.unwrap_or_else(|| std::path::PathBuf::from("priv_key.pem"));
                let carrier = tgt_loc.unwrap_or_else(|| { eprintln!("Error: --tgt_loc (carrier image) is required for --inject"); std::process::exit(1); });
                let key_data = fs::read(&key_path).unwrap_or_else(|_| { eprintln!("Error: Failed to read private key from {:?}", key_path); std::process::exit(1); });
                
                let mut out_path = carrier.clone();
                let stem = carrier.file_stem().unwrap_or_default().to_string_lossy();
                out_path.set_file_name(format!("{}_stego.png", stem));
                
                stego::inject_lsb(&carrier, &out_path, &key_data).unwrap_or_else(|e| { eprintln!("Stego Injection Error: {}", e); std::process::exit(1); });
                println!("Steganography injection successful. Weaponized image saved to: {:?}", out_path);
            } else if extract {
                let carrier = src_loc.unwrap_or_else(|| { eprintln!("Error: --src_loc (stego image) is required for --extract"); std::process::exit(1); });
                let key_path = privkey_loc.unwrap_or_else(|| std::path::PathBuf::from("priv_key.pem"));
                
                let bytes = stego::extract_lsb(&carrier).unwrap_or_else(|e| { eprintln!("Stego Extraction Error: {}", e); std::process::exit(1); });
                fs::write(&key_path, bytes).unwrap_or_else(|_| { eprintln!("Error: Failed to write extracted key to {:?}", key_path); std::process::exit(1); });
                println!("Steganography extraction successful. Key saved to: {:?}", key_path);
            } else {
                eprintln!("Error: Must specify either --inject or --extract");
                std::process::exit(1);
            }
        }
        Commands::Yubikey { genhmacsha1, pass, tgt_loc, yubikey_direct, yubikey_direct_touch } => {
            if genhmacsha1 {
                yubikey::generate_hmac_secret(pass, tgt_loc, yubikey_direct, yubikey_direct_touch);
            }
        }
    }
}
