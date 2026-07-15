use eframe::egui;

pub fn run_gui() {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1050.0, 600.0])
            .with_min_inner_size([850.0, 300.0]),
        ..Default::default()
    };
    
    eframe::run_native(
        "qcrypt GUI",
        options,
        Box::new(|_cc| Ok(Box::new(QcryptApp::default()))),
    ).unwrap();
}

#[derive(Default)]
struct QcryptApp {
    selected_tab: Tab,
    passphrase: String,
    nopemhead: bool,
    input_path: String,
    output_path: String,
    key_path: String,
    status_message: String,
    passphrase_confirm: String,
    target_network: TargetNetwork,
    pinata_jwt: String,
    arweave_eth_key: String,
    enc_payload_source: InputSource,
    enc_key_source: KeySource,
    enc_target_network: TargetNetwork,
    enc_arweave_use_yubikey: bool,
    enc_arweave_yubikey_salt: String,
    dec_payload_source: InputSource,
    dec_key_source: KeySource,
    ipfs_gateway: String,
    keygen_use_stego: bool,
    keygen_stego_carrier: String,
    decrypt_is_stego: bool,
    stego_mode: StegoMode,
    stego_src_loc: String,
    stego_privkey_loc: String,
    stego_tgt_loc: String,
    keygen_eth_output_path: String,
    keygen_eth_mode: crate::hybrid::AuthMode,
    keygen_eth_salt: String,
    keygen_eth_passphrase: String,
    keygen_auth_mode: crate::hybrid::AuthMode,
    decrypt_auth_mode: crate::hybrid::AuthMode,
    
    // Forensic tab specific
    forensic_recover_key_source: KeySource,
    forensic_recover_privkey_path: String,
    forensic_recover_out_path: String,
    forensic_recover_stego: bool,
    forensic_recover_nopemhead: bool,
    forensic_recover_auth_mode: crate::hybrid::AuthMode,
    
    // Yubikey Tab Specific
    yubikey_direct: bool,
    yubikey_direct_touch: bool,
}

impl QcryptApp {
    fn log_status(&mut self, msg: &str) {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.status_message.push_str(&format!("[{}] {}\n", now, msg));
    }
}

#[derive(Default, PartialEq)]
enum InputSource {
    #[default]
    Local,
    Net,
    Ipfs,
}

#[derive(Default, PartialEq)]
enum KeySource {
    #[default]
    Local,
    Net,
    Ipfs,
}

#[derive(Default, PartialEq)]
enum TargetNetwork {
    #[default]
    Local,
    Ipfs,
    Arweave,
}

fn mandatory_label(ui: &mut egui::Ui, text: &str) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 2.0;
        ui.label(egui::RichText::new("*").color(egui::Color32::RED));
        ui.label(text);
    });
}

fn file_picker_ui(ui: &mut egui::Ui, path_buffer: &mut String, label: &str, filters: &[(&str, &[&str])], is_mandatory: bool, is_save: bool) {
    ui.horizontal(|ui| {
        if is_mandatory {
            mandatory_label(ui, label);
        } else {
            ui.label(label);
        }
        
        ui.add(egui::TextEdit::singleline(path_buffer).desired_width(400.0));
        
        if ui.button("Browse...").clicked() {
            let mut dialog = rfd::FileDialog::new();
            for (name, exts) in filters {
                dialog = dialog.add_filter(*name, *exts);
            }
            let path_opt = if is_save {
                dialog.save_file()
            } else {
                dialog.pick_file()
            };
            if let Some(path) = path_opt {
                *path_buffer = path.to_string_lossy().to_string();
            }
        }
    });
}

#[derive(Default, PartialEq)]
enum StegoMode {
    #[default]
    Inject,
    Extract,
}

#[derive(Default, PartialEq)]
enum Tab {
    #[default]
    Keygen,
    KeygenEth,
    Encrypt,
    Decrypt,
    Stego,
    Forensic,
    Yubikey,
}

impl eframe::App for QcryptApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut visuals = egui::Visuals::dark();
        visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, egui::Color32::GRAY);
        visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, egui::Color32::LIGHT_GRAY);
        ctx.set_visuals(visuals);

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.selected_tab, Tab::Keygen, "Keygen");
                ui.selectable_value(&mut self.selected_tab, Tab::KeygenEth, "Keygen (ETH)");
                ui.selectable_value(&mut self.selected_tab, Tab::Encrypt, "Encrypt");
                ui.selectable_value(&mut self.selected_tab, Tab::Decrypt, "Decrypt");
                ui.selectable_value(&mut self.selected_tab, Tab::Stego, "Steganography");
                ui.selectable_value(&mut self.selected_tab, Tab::Forensic, "Forensic");
                ui.selectable_value(&mut self.selected_tab, Tab::Yubikey, "Yubikey");
            });
        });

        egui::TopBottomPanel::bottom("status_panel").show(ctx, |ui| {
            ui.add_space(5.0);
            ui.heading("Status:");
            egui::ScrollArea::vertical().max_height(150.0).stick_to_bottom(true).show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.status_message)
                        .desired_rows(8)
                        .font(egui::TextStyle::Monospace)
                        .text_color(egui::Color32::LIGHT_GREEN)
                        .interactive(true)
                        .desired_width(f32::INFINITY),
                );
            });
            ui.separator();
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                ui.label(egui::RichText::new("*").color(egui::Color32::RED));
                ui.label("Mandatory Field");
            });
            ui.add_space(5.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.selected_tab {
                Tab::Keygen => {
                    ui.heading("Key Generation");
                    ui.label("Generate Post-Quantum Key Pairs.");
                    ui.separator();
                    ui.label("Authentication Mode:");
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.keygen_auth_mode, crate::hybrid::AuthMode::Passphrase, "Passphrase Only");
                        ui.radio_value(&mut self.keygen_auth_mode, crate::hybrid::AuthMode::HardwareOnly, "Hardware Token Only");
                        ui.radio_value(&mut self.keygen_auth_mode, crate::hybrid::AuthMode::HardwareAndPassphrase, "Hardware Token + Passphrase");
                    });
                    ui.add_space(5.0);

                    if self.keygen_auth_mode != crate::hybrid::AuthMode::HardwareOnly {
                        ui.horizontal(|ui| {
                            mandatory_label(ui, "Passphrase:");
                            ui.add(egui::TextEdit::singleline(&mut self.passphrase).password(true));
                        });
                        ui.horizontal(|ui| {
                            mandatory_label(ui, "Confirm Passphrase:");
                            ui.add(egui::TextEdit::singleline(&mut self.passphrase_confirm).password(true));
                        });
                    }
                    ui.checkbox(&mut self.nopemhead, "Stealth Mode (No PEM Headers)");
                    
                    ui.separator();
                    ui.label("Target Network:");
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.target_network, TargetNetwork::Local, "Local Storage (Default)");
                        ui.radio_value(&mut self.target_network, TargetNetwork::Ipfs, "IPFS (Pinata)");
                        ui.radio_value(&mut self.target_network, TargetNetwork::Arweave, "Arweave (Irys)");
                    });

                    match self.target_network {
                        TargetNetwork::Local => {
                            ui.checkbox(&mut self.keygen_use_stego, "Bake Key into Image (Steganography)");
                            if self.keygen_use_stego {
                                file_picker_ui(ui, &mut self.keygen_stego_carrier, "Carrier PNG Path:", &[("Images", &["png", "bmp"])], true, false);
                            }
                        }
                        TargetNetwork::Ipfs => {
                            ui.horizontal(|ui| {
                                mandatory_label(ui, "Pinata JWT Token:");
                                ui.add(egui::TextEdit::singleline(&mut self.pinata_jwt).password(true));
                            });
                        }
                        TargetNetwork::Arweave => {
                            ui.horizontal(|ui| {
                                mandatory_label(ui, "ETH Key Hex/Path:");
                                ui.add(egui::TextEdit::singleline(&mut self.arweave_eth_key).password(true));
                            });
                        }
                    }
                    ui.separator();

                    if ui.button("Generate Keys").clicked() {
                        let pass1 = if self.keygen_auth_mode == crate::hybrid::AuthMode::HardwareOnly {
                            String::new()
                        } else {
                            self.passphrase.clone()
                        };

                        if self.keygen_auth_mode != crate::hybrid::AuthMode::HardwareOnly && self.passphrase != self.passphrase_confirm {
                            self.log_status("Passphrases do not match. Aborting.");
                        } else if self.keygen_auth_mode != crate::hybrid::AuthMode::HardwareOnly && self.passphrase.len() < 16 {
                            self.log_status("Passphrase rejected: Must be at least 16 characters.");
                        } else {
                            if self.keygen_auth_mode != crate::hybrid::AuthMode::Passphrase {
                                self.log_status("Please touch your YubiKey...");
                            }
                            let zero_pass = zeroize::Zeroizing::new(pass1);
                            let (priv_pem, pub_pem) = crate::hybrid::generate_keys(&zero_pass, self.nopemhead, &self.keygen_auth_mode);
                            match self.target_network {
                                TargetNetwork::Ipfs => {
                                    if self.pinata_jwt.is_empty() {
                                        self.log_status("Error: Pinata JWT Token required for IPFS upload.");
                                    } else {
                                        match (
                                            crate::ipfs::upload_to_ipfs(priv_pem.as_bytes(), &self.pinata_jwt),
                                            crate::ipfs::upload_to_ipfs(pub_pem.as_bytes(), &self.pinata_jwt)
                                        ) {
                                            (Ok(priv_cid), Ok(pub_cid)) => {
                                                if std::fs::write("priv_key.cid", priv_cid).is_ok() && std::fs::write("pub_key.cid", pub_cid).is_ok() {
                                                    self.log_status("Keys generated and injected to IPFS. (.cid files saved locally)");
                                                } else {
                                                    self.log_status("Error writing .cid files.");
                                                }
                                            }
                                            (Err(e), _) | (_, Err(e)) => {
                                                self.log_status(&format!("IPFS Upload Error: {}", e));
                                            }
                                        }
                                    }
                                }
                                TargetNetwork::Arweave => {
                                    if self.arweave_eth_key.is_empty() {
                                        self.log_status("Error: ETH Key required for Arweave upload.");
                                    } else {
                                        match (
                                            crate::arweave::upload_to_irys(priv_pem.as_bytes(), &self.arweave_eth_key),
                                            crate::arweave::upload_to_irys(pub_pem.as_bytes(), &self.arweave_eth_key)
                                        ) {
                                            (Ok(priv_txid), Ok(pub_txid)) => {
                                                let clean_priv = if priv_txid.contains("\"id\":\"") { priv_txid.split("\"id\":\"").nth(1).unwrap_or(&priv_txid).split("\"").next().unwrap_or(&priv_txid).to_string() } else { priv_txid };
                                                let clean_pub = if pub_txid.contains("\"id\":\"") { pub_txid.split("\"id\":\"").nth(1).unwrap_or(&pub_txid).split("\"").next().unwrap_or(&pub_txid).to_string() } else { pub_txid };
                                                
                                                if std::fs::write("priv_key.txid", clean_priv).is_ok() && std::fs::write("pub_key.txid", clean_pub).is_ok() {
                                                    self.log_status("Keys generated and injected to Arweave. (.txid files saved locally)");
                                                } else {
                                                    self.log_status("Error writing .txid files.");
                                                }
                                            }
                                            (Err(e), _) | (_, Err(e)) => {
                                                self.log_status(&format!("Arweave Upload Error: {}", e));
                                            }
                                        }
                                    }
                                }
                                TargetNetwork::Local => {
                                    if self.keygen_use_stego {
                                        if self.keygen_stego_carrier.is_empty() {
                                            self.log_status("Error: Carrier PNG Path required for Steganography.");
                                        } else {
                                            let carrier_path = std::path::Path::new(&self.keygen_stego_carrier);
                                            let out_path = std::path::PathBuf::from("priv_key_stego.png");
                                            if let Err(e) = crate::stego::inject_lsb(carrier_path, &out_path, priv_pem.as_bytes()) {
                                                self.log_status(&format!("Steganography Error: {}", e));
                                            } else {
                                                if let Err(e) = std::fs::write("pub_key.pem", pub_pem) {
                                                    self.log_status(&format!("Error writing pub_key.pem: {}", e));
                                                } else {
                                                    self.log_status("Keys generated successfully. Private key baked into 'priv_key_stego.png' and public key saved as 'pub_key.pem'");
                                                }
                                            }
                                        }
                                    } else {
                                        if let Err(e) = std::fs::write("priv_key.pem", priv_pem) {
                                            self.log_status(&format!("Error writing priv_key.pem: {}", e));
                                        } else if let Err(e) = std::fs::write("pub_key.pem", pub_pem) {
                                            self.log_status(&format!("Error writing pub_key.pem: {}", e));
                                        } else {
                                            self.log_status("Keys generated successfully as priv_key.pem and pub_key.pem");
                                        }
                                    }
                                }
                            }
                            self.passphrase.clear(); 
                            self.passphrase_confirm.clear();
                        }
                    }
                }
                Tab::KeygenEth => {
                    ui.heading("Random ETH Key Generation");
                    ui.label("Generate random Ethereum secp256k1 keys for Arweave uploads.");
                    
                    file_picker_ui(ui, &mut self.keygen_eth_output_path, "Output Path (Optional):", &[("Key File", &["key", "txt"])], false, true);
                    
                    ui.add_space(5.0);
                    if ui.button("Generate Random ETH Key").clicked() {
                        let secp = secp256k1::Secp256k1::new();
                        let (secret_key, _public_key) = secp.generate_keypair(&mut secp256k1::rand::rng());
                        let hex_key = format!("0x{}", secret_key.display_secret());
                        
                        let out_file = if self.keygen_eth_output_path.is_empty() {
                            std::path::PathBuf::from("ethereum.key")
                        } else {
                            std::path::PathBuf::from(&self.keygen_eth_output_path)
                        };
                        
                        if let Err(e) = std::fs::write(&out_file, &hex_key) {
                            self.log_status(&format!("Error writing {:?}: {}", out_file, e));
                        } else {
                            self.log_status(&format!("Random Ethereum Secp256k1 Private Key successfully generated and saved to: {:?}", out_file));
                        }
                    }
                    
                    ui.add_space(15.0);
                    ui.separator();
                    ui.add_space(15.0);
                    
                    ui.heading("Deterministic ETH Key Generation");
                    ui.label("Derive a reproducible key using a Passphrase or Hardware Token.");
                    
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.keygen_eth_mode, crate::hybrid::AuthMode::Passphrase, "Passphrase");
                        ui.radio_value(&mut self.keygen_eth_mode, crate::hybrid::AuthMode::HardwareOnly, "Hardware Token (YubiKey)");
                    });
                    
                    ui.add_space(10.0);
                    mandatory_label(ui, "Salt Phrase (Required):");
                    ui.add(egui::TextEdit::singleline(&mut self.keygen_eth_salt).desired_width(400.0).password(false));
                    
                    if self.keygen_eth_mode == crate::hybrid::AuthMode::Passphrase {
                        mandatory_label(ui, "Passphrase (Min 16 chars):");
                        ui.add(egui::TextEdit::singleline(&mut self.keygen_eth_passphrase).password(true).desired_width(400.0));
                    }
                    
                    ui.add_space(10.0);
                    if ui.button("Generate Deterministic ETH Key").clicked() {
                        let salt_val = self.keygen_eth_salt.trim();
                        if salt_val.is_empty() {
                            self.log_status("Error: Salt Phrase is mandatory for deterministic derivation.");
                        } else {
                            let pass_opt = if self.keygen_eth_mode == crate::hybrid::AuthMode::Passphrase {
                                Some(self.keygen_eth_passphrase.clone())
                            } else {
                                None
                            };
                            
                            let use_yubi = self.keygen_eth_mode == crate::hybrid::AuthMode::HardwareOnly;
                            
                            match crate::yubikey::derive_eth_key(pass_opt, use_yubi, salt_val) {
                                Ok(secret_key) => {
                                    let hex_key = format!("0x{}", secret_key.display_secret());
                                    
                                    let out_file = if self.keygen_eth_output_path.is_empty() {
                                        std::path::PathBuf::from("ethereum.key")
                                    } else {
                                        std::path::PathBuf::from(&self.keygen_eth_output_path)
                                    };
                                    
                                    if let Err(e) = std::fs::write(&out_file, &hex_key) {
                                        self.log_status(&format!("Error writing {:?}: {}", out_file, e));
                                    } else {
                                        self.log_status(&format!("Deterministic Ethereum Secp256k1 Private Key successfully generated and saved to: {:?}", out_file));
                                    }
                                }
                                Err(msg) => self.log_status(&format!("Derivation Error: {}", msg)),
                            }
                        }
                    }
                }
                Tab::Encrypt => {
                    ui.heading("Encryption");
                    ui.label("Encrypt payload with ML-KEM and AES-GCM.");
                    
                    ui.separator();
                    ui.label("Payload Source:");
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.enc_payload_source, InputSource::Local, "Local File");
                        ui.radio_value(&mut self.enc_payload_source, InputSource::Net, "HTTPS URL");
                        ui.radio_value(&mut self.enc_payload_source, InputSource::Ipfs, "IPFS CID");
                    });
                    ui.horizontal(|ui| {
                        if self.enc_payload_source == InputSource::Local {
                            file_picker_ui(ui, &mut self.input_path, "Input Path:", &[], true, false);
                        } else {
                            mandatory_label(ui, "Input URL/CID:");
                            ui.add(egui::TextEdit::singleline(&mut self.input_path).desired_width(400.0));
                        }
                    });

                    ui.separator();
                    ui.label("Public Key Source:");
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.enc_key_source, KeySource::Local, "Local File");
                        ui.radio_value(&mut self.enc_key_source, KeySource::Net, "HTTPS URL");
                        ui.radio_value(&mut self.enc_key_source, KeySource::Ipfs, "IPFS CID");
                    });
                    if self.enc_key_source == KeySource::Local {
                        file_picker_ui(ui, &mut self.key_path, "Key Path (Leave blank to use default pub_key.pem):", &[("PEM Key", &["pem"])], false, false);
                    } else {
                        ui.horizontal(|ui| {
                            mandatory_label(ui, "Key URL/CID:");
                            ui.add(egui::TextEdit::singleline(&mut self.key_path).desired_width(400.0));
                        });
                    }

                    if self.enc_payload_source == InputSource::Ipfs || self.enc_key_source == KeySource::Ipfs {
                        ui.separator();
                        ui.horizontal(|ui| {
                            ui.label("IPFS Gateway Override (Optional):");
                            ui.text_edit_singleline(&mut self.ipfs_gateway);
                        });
                    }

                    ui.separator();
                    ui.label("Output Destination:");
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.enc_target_network, TargetNetwork::Local, "Local Storage");
                        ui.radio_value(&mut self.enc_target_network, TargetNetwork::Ipfs, "IPFS (Pinata)");
                        ui.radio_value(&mut self.enc_target_network, TargetNetwork::Arweave, "Arweave (Irys)");
                    });

                    match self.enc_target_network {
                        TargetNetwork::Local => {}
                        TargetNetwork::Ipfs => {
                            ui.horizontal(|ui| {
                                mandatory_label(ui, "Pinata JWT Token:");
                                ui.add(egui::TextEdit::singleline(&mut self.pinata_jwt).password(true));
                            });
                        }
                        TargetNetwork::Arweave => {
                            ui.horizontal(|ui| {
                                ui.label("ETH Key Source:");
                                ui.radio_value(&mut self.enc_arweave_use_yubikey, false, "File / Raw Hex");
                                ui.radio_value(&mut self.enc_arweave_use_yubikey, true, "Hardware Token (YubiKey Slot 2)");
                            });
                            if self.enc_arweave_use_yubikey {
                                ui.horizontal(|ui| {
                                    mandatory_label(ui, "Salt Phrase:");
                                    ui.add(egui::TextEdit::singleline(&mut self.enc_arweave_yubikey_salt).password(true));
                                });
                            } else {
                                ui.horizontal(|ui| {
                                    mandatory_label(ui, "ETH Key Hex/Path:");
                                    ui.add(egui::TextEdit::singleline(&mut self.arweave_eth_key).password(true));
                                });
                            }
                        }
                    }

                    if self.enc_target_network == TargetNetwork::Local {
                        file_picker_ui(ui, &mut self.output_path, "Output Tracker Path (Leave blank for default):", &[("Encrypted Archive", &["enc"])], false, true);
                    } else {
                        ui.horizontal(|ui| {
                            ui.label("Output Tracker Path (Leave blank for default):");
                            ui.add(egui::TextEdit::singleline(&mut self.output_path).desired_width(400.0));
                        });
                    }
                    
                    ui.separator();
                    if ui.button("Encrypt Payload").clicked() {
                        let mut execute = || -> Result<(), String> {
                            // 1. Resolve Public Key
                            let pub_key_pem = match self.enc_key_source {
                                KeySource::Local => {
                                    let path = if self.key_path.is_empty() { "pub_key.pem".to_string() } else { self.key_path.clone() };
                                    std::fs::read_to_string(&path).map_err(|_| format!("Error: public key not found at {}", path))?
                                },
                                KeySource::Net => {
                                    if self.key_path.is_empty() { return Err("Error: HTTPS URL required for public key.".to_string()); }
                                    let resp = ureq::get(&self.key_path).call().map_err(|e| format!("Error fetching public key: {}", e))?;
                                    resp.into_string().map_err(|_| "Error reading public key string".to_string())?
                                },
                                KeySource::Ipfs => {
                                    if self.key_path.is_empty() { return Err("Error: IPFS CID required for public key.".to_string()); }
                                    let gateway = if self.ipfs_gateway.is_empty() { None } else { Some(&self.ipfs_gateway) };
                                    let url = crate::ipfs::resolve_ipfs(&self.key_path, gateway);
                                    let resp = ureq::get(&url).call().map_err(|e| format!("Error fetching public key from IPFS: {}", e))?;
                                    resp.into_string().map_err(|_| "Error reading public key string".to_string())?
                                },
                            };
                            
                            // 2. Resolve Payload Input
                            let (input, default_out): (Box<dyn std::io::Read + Send>, std::path::PathBuf) = match self.enc_payload_source {
                                InputSource::Local => {
                                    if self.input_path.is_empty() { return Err("Error: Input file path required.".to_string()); }
                                    let f = std::fs::File::open(&self.input_path).map_err(|_| "Error: Failed to open input file.".to_string())?;
                                    let out = std::path::PathBuf::from(&self.input_path);
                                    let mut os = out.into_os_string();
                                    os.push(".enc");
                                    (Box::new(f), std::path::PathBuf::from(os))
                                },
                                InputSource::Net => {
                                    if self.input_path.is_empty() { return Err("Error: HTTPS URL required for payload.".to_string()); }
                                    let resp = ureq::get(&self.input_path).call().map_err(|e| format!("Error fetching payload: {}", e))?;
                                    let def_name = self.input_path.split('/').last().unwrap_or("payload").to_string();
                                    (Box::new(resp.into_reader()), std::path::PathBuf::from(format!("{}.enc", def_name)))
                                },
                                InputSource::Ipfs => {
                                    if self.input_path.is_empty() { return Err("Error: IPFS CID required for payload.".to_string()); }
                                    let gateway = if self.ipfs_gateway.is_empty() { None } else { Some(&self.ipfs_gateway) };
                                    let url = crate::ipfs::resolve_ipfs(&self.input_path, gateway);
                                    let resp = ureq::get(&url).call().map_err(|e| format!("Error fetching payload from IPFS: {}", e))?;
                                    (Box::new(resp.into_reader()), std::path::PathBuf::from(format!("{}.enc", self.input_path)))
                                }
                            };
                            
                            let out_path = if self.output_path.is_empty() { default_out } else { std::path::PathBuf::from(&self.output_path) };
                            let zero_pub_key = zeroize::Zeroizing::new(pub_key_pem);
                            
                            // 3. Encrypt and route to destination
                            match self.target_network {
                                TargetNetwork::Ipfs => {
                                    if self.pinata_jwt.is_empty() { return Err("Error: Pinata JWT required for IPFS upload.".to_string()); }
                                    let buffer = std::io::Cursor::new(Vec::new());
                                    let mut buffer = crate::hybrid::encrypt_stream(input, buffer, &zero_pub_key).map_err(|e| format!("Encryption Error: {}", e))?;
                                    buffer.set_position(0);
                                    let cid = crate::ipfs::stream_to_ipfs(buffer, &self.pinata_jwt).map_err(|e| format!("IPFS Upload Error: {}", e))?;
                                    let out_f = if self.output_path.is_empty() { std::path::PathBuf::from("payload.cid") } else { std::path::PathBuf::from(&self.output_path) };
                                    std::fs::write(&out_f, &cid).map_err(|_| "Error writing .cid tracker file".to_string())?;
                                    self.log_status(&format!("File encrypted & uploaded to IPFS. CID saved to: {:?}", out_f));
                                },
                                TargetNetwork::Arweave => {
                                    let eth_key_str = if self.enc_arweave_use_yubikey {
                                        if self.enc_arweave_yubikey_salt.is_empty() { return Err("Error: Salt Phrase required for YubiKey derivation.".to_string()); }
                                        let sk = crate::yubikey::derive_eth_key(None, true, &self.enc_arweave_yubikey_salt)
                                            .map_err(|e| format!("Hardware Derivation Error: {}", e))?;
                                        format!("0x{}", sk.display_secret())
                                    } else {
                                        if self.arweave_eth_key.is_empty() { return Err("Error: ETH Key required for Arweave upload.".to_string()); }
                                        self.arweave_eth_key.clone()
                                    };
                                    
                                    let buffer = std::io::Cursor::new(Vec::new());
                                    let buffer = crate::hybrid::encrypt_stream(input, buffer, &zero_pub_key).map_err(|e| format!("Encryption Error: {}", e))?;
                                    let data = buffer.into_inner();
                                    if data.len() > 100 * 1024 && !crate::arweave::has_irys_balance(&eth_key_str) {
                                        return Err(format!("Error: Encrypted size {} bytes. Irys free tier < 100KB, wallet has no balance.", data.len()));
                                    }
                                    let txid = crate::arweave::upload_to_irys(&data, &eth_key_str).map_err(|e| format!("Arweave Upload Error: {}", e))?;
                                    let clean_txid = if txid.contains("\"id\":\"") { txid.split("\"id\":\"").nth(1).unwrap_or(&txid).split("\"").next().unwrap_or(&txid).to_string() } else { txid };
                                    let out_f = if self.output_path.is_empty() { std::path::PathBuf::from("payload.txid") } else { std::path::PathBuf::from(&self.output_path) };
                                    std::fs::write(&out_f, &clean_txid).map_err(|_| "Error writing .txid tracker file".to_string())?;
                                    self.log_status(&format!("File encrypted & uploaded to Arweave. TxID saved to: {:?}", out_f));
                                },
                                TargetNetwork::Local => {
                                    let output = std::fs::File::create(&out_path).map_err(|_| format!("Error: Failed to create output file: {:?}", out_path))?;
                                    crate::hybrid::encrypt_stream(input, output.try_clone().unwrap(), &zero_pub_key).map_err(|e| format!("Encryption Error: {}", e))?;
                                    self.log_status(&format!("File encrypted successfully to: {:?}", out_path));
                                }
                            }
                            
                            Ok(())
                        };
                        
                        if let Err(msg) = execute() {
                            self.log_status(&msg);
                        }
                    }
                }
                Tab::Decrypt => {
                    ui.heading("Decryption");
                    ui.label("Decrypt archive with private key.");
                    
                    ui.separator();
                    ui.label("Encrypted Payload Source:");
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.dec_payload_source, InputSource::Local, "Local File");
                        ui.radio_value(&mut self.dec_payload_source, InputSource::Net, "HTTPS URL");
                        ui.radio_value(&mut self.dec_payload_source, InputSource::Ipfs, "IPFS CID");
                    });
                    ui.horizontal(|ui| {
                        if self.dec_payload_source == InputSource::Local {
                            file_picker_ui(ui, &mut self.input_path, "Input Path:", &[("Encrypted Archive", &["enc"])], true, false);
                        } else {
                            mandatory_label(ui, "Input URL/CID:");
                            ui.add(egui::TextEdit::singleline(&mut self.input_path).desired_width(400.0));
                        }
                    });

                    ui.separator();
                    ui.label("Private Key Source:");
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.dec_key_source, KeySource::Local, "Local File");
                        ui.radio_value(&mut self.dec_key_source, KeySource::Net, "HTTPS URL");
                        ui.radio_value(&mut self.dec_key_source, KeySource::Ipfs, "IPFS CID");
                    });
                    if self.dec_key_source == KeySource::Local {
                        file_picker_ui(ui, &mut self.key_path, "Key Path (Leave blank to use default priv_key.pem):", &[("PEM Key or Carrier", &["pem", "png", "bmp"])], false, false);
                    } else {
                        ui.horizontal(|ui| {
                            mandatory_label(ui, "Key URL/CID:");
                            ui.add(egui::TextEdit::singleline(&mut self.key_path).desired_width(400.0));
                        });
                    }
                    
                    ui.checkbox(&mut self.decrypt_is_stego, "Key is hidden in a Steganographic Carrier");
                    
                    ui.separator();
                    ui.label("Authentication Mode:");
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.decrypt_auth_mode, crate::hybrid::AuthMode::Passphrase, "Passphrase Only");
                        ui.radio_value(&mut self.decrypt_auth_mode, crate::hybrid::AuthMode::HardwareOnly, "Hardware Token Only");
                        ui.radio_value(&mut self.decrypt_auth_mode, crate::hybrid::AuthMode::HardwareAndPassphrase, "Hardware Token + Passphrase");
                    });
                    ui.add_space(5.0);

                    if self.decrypt_auth_mode != crate::hybrid::AuthMode::HardwareOnly {
                        ui.horizontal(|ui| {
                            mandatory_label(ui, "Passphrase:");
                            ui.add(egui::TextEdit::singleline(&mut self.passphrase).password(true));
                        });
                    }

                    if self.dec_payload_source == InputSource::Ipfs || self.dec_key_source == KeySource::Ipfs {
                        ui.separator();
                        ui.horizontal(|ui| {
                            ui.label("IPFS Gateway Override (Optional):");
                            ui.text_edit_singleline(&mut self.ipfs_gateway);
                        });
                    }

                    ui.separator();
                    ui.label("Output Destination:");
                    file_picker_ui(ui, &mut self.output_path, "Output Path (Leave blank to auto-strip .enc):", &[], false, true);
                    
                    ui.separator();
                    if ui.button("Decrypt Payload").clicked() {
                        let mut execute = || -> Result<(), String> {
                            if self.decrypt_auth_mode != crate::hybrid::AuthMode::HardwareOnly && self.passphrase.is_empty() { return Err("Error: Passphrase required for decryption.".to_string()); }
                            
                            let pass_input = if self.decrypt_auth_mode == crate::hybrid::AuthMode::HardwareOnly {
                                String::new()
                            } else {
                                self.passphrase.clone()
                            };
                            
                            if self.decrypt_auth_mode != crate::hybrid::AuthMode::Passphrase {
                                self.log_status("Please touch your YubiKey...");
                            }
                            
                            // 1. Resolve Private Key
                            let priv_key_pem = match self.dec_key_source {
                                KeySource::Local => {
                                    let path = if self.key_path.is_empty() { 
                                        if self.decrypt_is_stego { "priv_key_stego.png".to_string() } else { "priv_key.pem".to_string() }
                                    } else { 
                                        self.key_path.clone() 
                                    };
                                    
                                    if self.decrypt_is_stego {
                                        let bytes = crate::stego::extract_lsb(std::path::Path::new(&path)).map_err(|e| format!("Stego Extraction Error: {}", e))?;
                                        String::from_utf8_lossy(&bytes).into_owned()
                                    } else {
                                        std::fs::read_to_string(&path).map_err(|_| format!("Error: private key not found at {}", path))?
                                    }
                                },
                                KeySource::Net => {
                                    if self.key_path.is_empty() { return Err("Error: HTTPS URL required for private key.".to_string()); }
                                    let mut reader = ureq::get(&self.key_path).call().map_err(|e| format!("Error fetching private key: {}", e))?.into_reader();
                                    let mut bytes = Vec::new();
                                    std::io::Read::read_to_end(&mut reader, &mut bytes).map_err(|_| "Error reading private key stream".to_string())?;
                                    
                                    if self.decrypt_is_stego {
                                        let ext = crate::stego::extract_lsb_from_memory(&bytes).map_err(|e| format!("Stego Extraction Error: {}", e))?;
                                        String::from_utf8_lossy(&ext).into_owned()
                                    } else {
                                        String::from_utf8_lossy(&bytes).into_owned()
                                    }
                                },
                                KeySource::Ipfs => {
                                    if self.key_path.is_empty() { return Err("Error: IPFS CID required for private key.".to_string()); }
                                    let gateway = if self.ipfs_gateway.is_empty() { None } else { Some(&self.ipfs_gateway) };
                                    let url = crate::ipfs::resolve_ipfs(&self.key_path, gateway);
                                    let mut reader = ureq::get(&url).call().map_err(|e| format!("Error fetching private key from IPFS: {}", e))?.into_reader();
                                    let mut bytes = Vec::new();
                                    std::io::Read::read_to_end(&mut reader, &mut bytes).map_err(|_| "Error reading private key stream".to_string())?;
                                    
                                    if self.decrypt_is_stego {
                                        let ext = crate::stego::extract_lsb_from_memory(&bytes).map_err(|e| format!("Stego Extraction Error: {}", e))?;
                                        String::from_utf8_lossy(&ext).into_owned()
                                    } else {
                                        String::from_utf8_lossy(&bytes).into_owned()
                                    }
                                },
                            };
                            
                            // 2. Resolve Payload Input
                            let (input, default_out): (Box<dyn std::io::Read + Send>, std::path::PathBuf) = match self.dec_payload_source {
                                InputSource::Local => {
                                    if self.input_path.is_empty() { return Err("Error: Input file path required.".to_string()); }
                                    let f = std::fs::File::open(&self.input_path).map_err(|_| "Error: Failed to open encrypted archive. Please check the path.".to_string())?;
                                    let out = std::path::PathBuf::from(&self.input_path).with_extension("");
                                    (Box::new(f), out)
                                },
                                InputSource::Net => {
                                    if self.input_path.is_empty() { return Err("Error: HTTPS URL required for payload.".to_string()); }
                                    let resp = ureq::get(&self.input_path).call().map_err(|e| format!("Error fetching payload: {}", e))?;
                                    let def_name = self.input_path.split('/').last().unwrap_or("payload.enc").to_string();
                                    let stripped_name = if def_name.ends_with(".enc") { def_name.strip_suffix(".enc").unwrap().to_string() } else { format!("{}.dec", def_name) };
                                    (Box::new(resp.into_reader()), std::path::PathBuf::from(stripped_name))
                                },
                                InputSource::Ipfs => {
                                    if self.input_path.is_empty() { return Err("Error: IPFS CID required for payload.".to_string()); }
                                    let gateway = if self.ipfs_gateway.is_empty() { None } else { Some(&self.ipfs_gateway) };
                                    let url = crate::ipfs::resolve_ipfs(&self.input_path, gateway);
                                    let resp = ureq::get(&url).call().map_err(|e| format!("Error fetching payload from IPFS: {}", e))?;
                                    (Box::new(resp.into_reader()), std::path::PathBuf::from(format!("{}.dec", self.input_path)))
                                }
                            };
                            
                            let out_path = if self.output_path.is_empty() { default_out } else { std::path::PathBuf::from(&self.output_path) };
                            
                            let zero_pass = zeroize::Zeroizing::new(pass_input);
                            let output = std::fs::File::create(&out_path).map_err(|_| format!("Error: Failed to create decrypted file: {:?}", out_path))?;
                            
                            crate::hybrid::decrypt_stream(input, output.try_clone().unwrap(), &priv_key_pem, &zero_pass, &self.decrypt_auth_mode).map_err(|e| format!("Decryption Error: {}", e))?;
                            
                            self.log_status(&format!("File decrypted successfully to: {:?}", out_path));
                            Ok(())
                        };
                        
                        if let Err(msg) = execute() {
                            self.log_status(&msg);
                        }
                    }
                }
                Tab::Forensic => {
                    ui.heading("Forensic Analysis");
                    ui.label("Scan encrypted archive for corruption.");
                    file_picker_ui(ui, &mut self.input_path, "Input Archive:", &[("Encrypted Archive", &["enc"])], true, false);
                    if ui.button("Scan Archive").clicked() {
                        let mut execute = || -> Result<(), String> {
                            if self.input_path.is_empty() { return Err("Error: Input archive path required.".to_string()); }
                            let path = std::path::PathBuf::from(&self.input_path);
                            
                            self.log_status(&format!("Starting forensic scan on: {:?}", path));
                            
                            // Note: detailed forensic data is currently logged to console (stderr)
                            crate::forensic::forensic_scan(&path).map_err(|e| format!("Forensic Error: {}", e))?;
                            
                            self.log_status(&format!("Scan Complete. No structural corruption detected in payload chunks."));
                            Ok(())
                        };
                        if let Err(e) = execute() {
                            self.log_status(&e);
                        }
                    }
                    
                    ui.add_space(20.0);
                    ui.separator();
                    ui.add_space(10.0);
                    
                    ui.heading("Public Key Recovery");
                    ui.label("Regenerate a lost pub_key.pem from an existing priv_key.pem.");
                    
                    ui.horizontal(|ui| {
                        ui.label("Private Key Source:");
                        ui.radio_value(&mut self.forensic_recover_key_source, KeySource::Local, "Local File");
                        ui.radio_value(&mut self.forensic_recover_key_source, KeySource::Net, "HTTPS URL");
                        ui.radio_value(&mut self.forensic_recover_key_source, KeySource::Ipfs, "IPFS CID");
                    });
                    
                    if self.forensic_recover_key_source == KeySource::Local {
                        file_picker_ui(ui, &mut self.forensic_recover_privkey_path, "Private Key Path:", &[("PEM Key or Carrier", &["pem", "png", "bmp"])], true, false);
                    } else {
                        ui.horizontal(|ui| {
                            mandatory_label(ui, "Private Key URL/CID:");
                            ui.add(egui::TextEdit::singleline(&mut self.forensic_recover_privkey_path).desired_width(400.0));
                        });
                    }
                    
                    if self.forensic_recover_key_source == KeySource::Ipfs {
                        ui.horizontal(|ui| {
                            ui.label("IPFS Gateway (Optional):");
                            ui.add(egui::TextEdit::singleline(&mut self.ipfs_gateway));
                        });
                    }
                    
                    file_picker_ui(ui, &mut self.forensic_recover_out_path, "Target Output Path (Leave blank to use default pub_key.pem):", &[], false, true);
                    
                    ui.checkbox(&mut self.forensic_recover_stego, "Private Key is embedded in a PNG Carrier (Steganography)");
                    ui.checkbox(&mut self.forensic_recover_nopemhead, "Generate Headerless Stealth Key");
                    
                    ui.horizontal(|ui| {
                        ui.label("Auth Mode:");
                        ui.radio_value(&mut self.forensic_recover_auth_mode, crate::hybrid::AuthMode::Passphrase, "Passphrase Only");
                        ui.radio_value(&mut self.forensic_recover_auth_mode, crate::hybrid::AuthMode::HardwareOnly, "YubiKey Only");
                        ui.radio_value(&mut self.forensic_recover_auth_mode, crate::hybrid::AuthMode::HardwareAndPassphrase, "YubiKey + Passphrase");
                    });
                    
                    if self.forensic_recover_auth_mode != crate::hybrid::AuthMode::HardwareOnly {
                        ui.horizontal(|ui| {
                            mandatory_label(ui, "Passphrase:");
                            ui.add(egui::TextEdit::singleline(&mut self.passphrase).password(true));
                        });
                    }
                    
                    if ui.button("Regenerate Public Key").clicked() {
                        let mut execute = || -> Result<(), String> {
                            let pass_input = if self.forensic_recover_auth_mode == crate::hybrid::AuthMode::HardwareOnly {
                                String::new()
                            } else {
                                if self.passphrase.is_empty() {
                                    return Err("Error: Passphrase required.".to_string());
                                }
                                self.passphrase.clone()
                            };
                            
                            if self.forensic_recover_auth_mode != crate::hybrid::AuthMode::Passphrase {
                                self.log_status("Please touch your YubiKey...");
                            }
                            
                            let priv_key_pem = match self.forensic_recover_key_source {
                                KeySource::Local => {
                                    let path = if self.forensic_recover_privkey_path.is_empty() { 
                                        if self.forensic_recover_stego { "priv_key_stego.png".to_string() } else { "priv_key.pem".to_string() }
                                    } else { 
                                        self.forensic_recover_privkey_path.clone() 
                                    };
                                    
                                    if self.forensic_recover_stego {
                                        let bytes = crate::stego::extract_lsb(std::path::Path::new(&path)).map_err(|e| format!("Stego Extraction Error: {}", e))?;
                                        String::from_utf8_lossy(&bytes).into_owned()
                                    } else {
                                        std::fs::read_to_string(&path).map_err(|_| format!("Error: private key not found at {}", path))?
                                    }
                                },
                                KeySource::Net => {
                                    if self.forensic_recover_privkey_path.is_empty() { return Err("Error: HTTPS URL required for private key.".to_string()); }
                                    let mut reader = ureq::get(&self.forensic_recover_privkey_path).call().map_err(|e| format!("Error fetching private key: {}", e))?.into_reader();
                                    let mut bytes = Vec::new();
                                    std::io::Read::read_to_end(&mut reader, &mut bytes).map_err(|_| "Error reading private key stream".to_string())?;
                                    
                                    if self.forensic_recover_stego {
                                        let ext = crate::stego::extract_lsb_from_memory(&bytes).map_err(|e| format!("Stego Extraction Error: {}", e))?;
                                        String::from_utf8_lossy(&ext).into_owned()
                                    } else {
                                        String::from_utf8_lossy(&bytes).into_owned()
                                    }
                                },
                                KeySource::Ipfs => {
                                    if self.forensic_recover_privkey_path.is_empty() { return Err("Error: IPFS CID required for private key.".to_string()); }
                                    let gateway = if self.ipfs_gateway.is_empty() { None } else { Some(&self.ipfs_gateway) };
                                    let url = crate::ipfs::resolve_ipfs(&self.forensic_recover_privkey_path, gateway);
                                    let mut reader = ureq::get(&url).call().map_err(|e| format!("Error fetching private key from IPFS: {}", e))?.into_reader();
                                    let mut bytes = Vec::new();
                                    std::io::Read::read_to_end(&mut reader, &mut bytes).map_err(|_| "Error reading private key stream".to_string())?;
                                    
                                    if self.forensic_recover_stego {
                                        let ext = crate::stego::extract_lsb_from_memory(&bytes).map_err(|e| format!("Stego Extraction Error: {}", e))?;
                                        String::from_utf8_lossy(&ext).into_owned()
                                    } else {
                                        String::from_utf8_lossy(&bytes).into_owned()
                                    }
                                }
                            };
                            
                            let zero_pass = zeroize::Zeroizing::new(pass_input);
                            
                            let pub_pem = crate::hybrid::recover_public_key(
                                &priv_key_pem, 
                                &zero_pass, 
                                &self.forensic_recover_auth_mode, 
                                self.forensic_recover_nopemhead
                            ).map_err(|e| format!("Recovery Error: {}", e))?;
                            
                            let default_out = "pub_key.pem".to_string();
                            let out_path = if self.forensic_recover_out_path.is_empty() { &default_out } else { &self.forensic_recover_out_path };
                            
                            std::fs::write(&out_path, pub_pem).map_err(|_| format!("Error: Failed to write to {:?}", out_path))?;
                            
                            self.log_status(&format!("Success! Public Key regenerated and saved to: {}", out_path));
                            Ok(())
                        };
                        
                        if let Err(msg) = execute() {
                            self.log_status(&msg);
                        }
                    }
                }
                Tab::Stego => {
                    ui.heading("Steganography Engine");
                    ui.label("Raw LSB steganography operations for Key hiding.");
                    
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.stego_mode, StegoMode::Inject, "Inject Key");
                        ui.radio_value(&mut self.stego_mode, StegoMode::Extract, "Extract Key");
                    });
                    
                    ui.separator();
                    match self.stego_mode {
                        StegoMode::Inject => {
                            file_picker_ui(ui, &mut self.stego_privkey_loc, "Private Key Path (.pem):", &[("PEM Key", &["pem"])], true, false);
                            file_picker_ui(ui, &mut self.stego_tgt_loc, "Target Carrier Image (.png/.bmp):", &[("Images", &["png", "bmp"])], true, false);
                            ui.add_space(10.0);
                            if ui.button("Inject Key").clicked() {
                                let mut execute = || -> Result<(), String> {
                                    if self.stego_privkey_loc.is_empty() || self.stego_tgt_loc.is_empty() {
                                        return Err("Error: Key path and Carrier path required.".to_string());
                                    }
                                    let key_data = std::fs::read(&self.stego_privkey_loc).map_err(|_| "Failed to read private key".to_string())?;
                                    let carrier_path = std::path::Path::new(&self.stego_tgt_loc);
                                    let out_path = std::path::PathBuf::from("priv_key_stego.png");
                                    crate::stego::inject_lsb(carrier_path, &out_path, &key_data).map_err(|e| format!("Injection Error: {}", e))?;
                                    self.log_status("Injection complete. Key baked into 'priv_key_stego.png'");
                                    Ok(())
                                };
                                if let Err(e) = execute() {
                                    self.log_status(&e);
                                }
                            }
                        },
                        StegoMode::Extract => {
                            file_picker_ui(ui, &mut self.stego_src_loc, "Carrier Image (.png):", &[("Images", &["png", "bmp"])], true, false);
                            file_picker_ui(ui, &mut self.stego_privkey_loc, "Output Key Path (Optional):", &[("PEM Key", &["pem"])], false, true);
                            ui.add_space(10.0);
                            if ui.button("Extract Key").clicked() {
                                let mut execute = || -> Result<(), String> {
                                    if self.stego_src_loc.is_empty() {
                                        return Err("Error: Carrier Image path required.".to_string());
                                    }
                                    let bytes = crate::stego::extract_lsb(std::path::Path::new(&self.stego_src_loc)).map_err(|e| format!("Extraction Error: {}", e))?;
                                    let out_path = if self.stego_privkey_loc.is_empty() { "priv_key.pem".to_string() } else { self.stego_privkey_loc.clone() };
                                    std::fs::write(&out_path, bytes).map_err(|_| "Failed to write extracted key".to_string())?;
                                    self.log_status(&format!("Extraction complete. Key saved to '{}'", out_path));
                                    Ok(())
                                };
                                if let Err(e) = execute() {
                                    self.log_status(&e);
                                }
                            }
                        }
                    }
                }
                Tab::Yubikey => {
                    ui.heading("YubiKey Provisioning");
                    ui.label("Generate deterministic HMAC-SHA1 secrets from passphrases.");
                    ui.add_space(5.0);
                    ui.label(egui::RichText::new("Note: Import the generated hex key into Slot 2 of your YubiKey using YubiKey Manager (ykman).").color(egui::Color32::YELLOW));
                    ui.label(egui::RichText::new("Command: ykman otp chalresp 2 <40_char_hex_from_file>").monospace());
                    ui.label(egui::RichText::new("(Add '-t' to the command if you want to require physical touch for authentication)").color(egui::Color32::LIGHT_GRAY));
                    ui.add_space(5.0);
                    ui.label(egui::RichText::new("To read directly from the generated file:").color(egui::Color32::LIGHT_GRAY));
                    ui.label(egui::RichText::new("[PowerShell]: ykman otp chalresp 2 $(Get-Content hmac_sha1_key.hex)").monospace());
                    ui.label(egui::RichText::new("[Linux/Mac]:  ykman otp chalresp 2 $(cat hmac_sha1_key.hex)").monospace());
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        mandatory_label(ui, "Passphrase (min 16 chars):");
                        ui.add(egui::TextEdit::singleline(&mut self.passphrase).password(true));
                    });
                    ui.horizontal(|ui| {
                        mandatory_label(ui, "Confirm Passphrase:");
                        ui.add(egui::TextEdit::singleline(&mut self.passphrase_confirm).password(true));
                    });
                    ui.checkbox(&mut self.yubikey_direct, "Inject secret directly into YubiKey Slot 2 (Zero-Disk)");
                    if self.yubikey_direct {
                        ui.checkbox(&mut self.yubikey_direct_touch, "Require Physical Touch for Authentication (-t)");
                    } else {
                        file_picker_ui(ui, &mut self.output_path, "Output Path (Optional):", &[("Hex Key", &["hex"])], false, true);
                    }
                    ui.add_space(10.0);
                    if ui.button("Generate HMAC-SHA1 Hex Secret").clicked() {
                        if self.passphrase != self.passphrase_confirm {
                            self.log_status("Passphrases do not match. Aborting.");
                        } else if self.passphrase.len() < 16 {
                            self.log_status("Passphrase rejected: Must be at least 16 characters.");
                        } else {
                            let static_salt = b"qcrypt_yubi_salt";
                            let mut out = [0u8; 20];
                            argon2::Argon2::default().hash_password_into(self.passphrase.as_bytes(), static_salt, &mut out).expect("Argon2id derivation failed");
                            
                            if self.yubikey_direct {
                                self.log_status("Attempting direct injection to YubiKey...");
                                let require_touch = self.yubikey_direct_touch;
                                
                                match std::panic::catch_unwind(|| -> Result<(), String> {
                                    use yubikey_hmac_otp::Yubico;
                                    use yubikey_hmac_otp::config::{Config, Command};
                                    use yubikey_hmac_otp::configure::DeviceModeConfig;
                                    use yubikey_hmac_otp::hmacmode::HmacKey;
                                    
                                    let mut yubi = Yubico::new();
                                    let device = yubi.find_yubikey().map_err(|_| "YubiKey not detected. Aborting injection.")?;
                                    
                                    let config = Config::new_from(device)
                                        .set_command(Command::Configuration2);
                                        
                                    let hmac_key = HmacKey::from_slice(&out);
                                    let mut device_config = DeviceModeConfig::default();
                                    
                                    let variable_size = false; // We use a fixed 20-byte secret
                                    device_config.challenge_response_hmac(&hmac_key, variable_size, require_touch);
                                        
                                    yubi.write_config(config, &mut device_config)
                                        .map_err(|e| format!("Failed to write to YubiKey: {:?}", e))
                                }) {
                                    Ok(Ok(_)) => self.log_status("Secret Successfully Injected into YubiKey Slot 2!"),
                                    Ok(Err(msg)) => self.log_status(&msg),
                                    Err(_) => self.log_status("YubiKey interaction panicked or failed. Check PC/SC driver."),
                                }
                            } else {
                                use std::fmt::Write;
                                let mut hex_out = String::with_capacity(40);
                                for byte in &out {
                                    write!(&mut hex_out, "{:02x}", byte).unwrap();
                                }
                                
                                let out_file = if self.output_path.is_empty() {
                                    std::path::PathBuf::from("hmac_sha1_key.hex")
                                } else {
                                    std::path::PathBuf::from(&self.output_path)
                                };
                                
                                match std::fs::write(&out_file, &hex_out) {
                                    Ok(_) => self.log_status(&format!("Secret Generated! Saved to: {:?}", out_file)),
                                    Err(_) => self.log_status(&format!("Error writing to {:?}", out_file))
                                }
                            }
                        }
                    }
                }
            }
        });
    }
}
