use clap::{Parser, Subcommand};
use std::path::PathBuf;

const HELP_FOOTER: &str = "\
DETAILED USAGE & SUB-PARAMETERS:

1. KEYGEN
   qcrypt.exe keygen [--pass <string>] [--nopemhead] [--stego <CARRIER_PNG>] [--yubikey] [--yubikey_and_pass]
   Generates keypairs. If --pass is provided, it bypasses the interactive prompt.
   --nopemhead explicitly strips standard RFC 7468 PEM headers for stealth.
   --stego natively intercepts the private key during generation and injects it into the carrier PNG.
   --yubikey forces Hardware Token (Slot 2) authentication instead of a passphrase.
   --yubikey_and_pass requires BOTH Hardware Token and Passphrase (Hybrid Mode).

2. KEYGEN ETH
   qcrypt.exe keygen-eth [--tgt_loc <PATH>] [--deterministic] [--salt <STRING>] [--passphrase <STRING>] [--yubikey]
   Generates a raw Ethereum secp256k1 private key and saves it to `ethereum.key` (or specified path).
   If --deterministic is set, it derives the exact same 32-byte key mathematically from a user-provided --salt 
   plus either a --passphrase or the YubiKey HMAC hardware response (--yubikey).
   This key is used strictly for cryptographic signing during Irys zero-disk uploads.

3. ENCRYPT
   qcrypt.exe encrypt [--src_net <URL> | --src_loc <PATH> | --src_ipfs <CID>]
                      [--pubkey_net <URL> | --pubkey_loc <PATH> | --pubkey_ipfs <CID>]
                      [--tgt_loc <PATH>]
                      [--ipfs_gateway <TAG_OR_URL>]
   Encrypts a payload. Streams directly from the network, local disk, or decentralized IPFS swarm.

4. DECRYPT
   qcrypt.exe decrypt [--src_net <URL> | --src_loc <PATH> | --src_ipfs <CID>]
                      [--privkey_net <URL> | --privkey_loc <PATH> | --privkey_ipfs <CID>]
                      [--pass <string>] [--yubikey] [--yubikey_and_pass]
                      [--tgt_loc <PATH>]
                      [--ipfs_gateway <TAG_OR_URL>]
                      [--stego]
   Decrypts a payload using the matching key.
   --stego boolean flag routes the key pipeline to parse the --privkey_loc as a steganographic carrier.

5. FORENSIC
   qcrypt.exe forensic <FILE.enc>
   Scans an encrypted payload for structural corruption without requiring a key.
   
   qcrypt.exe forensic --keygen_pub [--privkey_net <URL> | --privkey_loc <PATH> | --privkey_ipfs <CID>]
                                    [--pass <string>] [--yubikey] [--yubikey_and_pass]
                                    [--stego] [--nopemhead] [--tgt_loc <PATH>]
   Regenerates the public key mathematically derived from the private key.

6. STEGO
   qcrypt.exe stego [--inject | --extract] [--src_loc <PATH>] [--privkey_loc <PATH>] [--tgt_loc <PATH>]
   Raw LSB steganography engine for manipulating keys inside PNG/BMP carrier images.
   --inject  : Injects a key. Requires --privkey_loc (the key) and --tgt_loc (the carrier photo).
   --extract : Extracts a key. Requires --src_loc (the carrier photo). Outputs to --privkey_loc.

6. YUBIKEY
   qcrypt.exe yubikey --genhmacsha1 [--pass <string>] [--tgt_loc <PATH>] [--yubikey_direct] [--yubikey_direct_touch]
   Generates a deterministic HMAC-SHA1 40-char Hex secret from your master passphrase.
   Use --yubikey_direct to inject the secret instantly into Slot 2 of a connected YubiKey (Zero-Disk).
   Use --yubikey_direct_touch to require physical touch when using the injected key.
   
   If injecting directly fails, or if not using injection, you can use the output file with `ykman`:
   [PowerShell]: ykman otp chalresp 2 $(Get-Content hmac_sha1_key.hex)
   [Linux/Mac]:  ykman otp chalresp 2 $(cat hmac_sha1_key.hex)

* IPFS ROUTING NOTE:
  [DOWNLOADS] When using --src_ipfs, --pubkey_ipfs, or --privkey_ipfs, the engine streams directly from IPFS.
  You can dynamically route this via the --ipfs_gateway flag:
   - Provide a tag (e.g. 'cloudflare', 'pinata') to match against live public gateways.
   - Provide a raw URL (e.g. 'http://127.0.0.1:8080/') to bypass scraping entirely.
   - Omit the flag entirely to default to 'https://ipfs.io'.

  [UPLOADS] To inject encrypted payloads and keys directly to the swarm (Zero-Disk footprint),
  provide a Web3 Authentication Identity:
   - --ipfs_pinata_jwt <TOKEN> : Implicitly routes the upload to Pinata's API.
   - --arweave_eth_key <HEX_OR_PATH> : Implicitly routes the upload to Arweave via Irys Node 2.
     (OR) use --yubikey_ethkey_useslot2 and --yubikey_ethkey_salt <STRING> to mathematically derive
     the Ethereum signing key directly from YubiKey hardware memory without touching the disk.

Note: Default cryptography assumes 'pub_key.pem' and 'priv_key.pem' in the current directory.
";

#[derive(Parser)]
#[command(author, version, about = "ML-KEM Hybrid Cryptography Tool")]
#[command(after_help = HELP_FOOTER)]
pub struct Cli {
    /// IPFS Gateway override (URL or tag like 'cloudflare', 'dweb', 'pinata') for downloads
    #[arg(long = "ipfs_gateway", global = true)]
    pub ipfs_gateway: Option<String>,
    
    /// IPFS Pinata API JWT Bearer Token for implicit upload routing
    #[arg(long = "ipfs_pinata_jwt", global = true)]
    pub ipfs_pinata_jwt: Option<String>,
    
    /// Arweave Irys Ethereum Signing Key (Hex String or File Path)
    #[arg(long = "arweave_eth_key", global = true)]
    pub arweave_eth_key: Option<String>,
    
    /// Derive Arweave Irys Ethereum Signing Key directly from YubiKey Slot 2 (Zero-Disk)
    #[arg(long = "yubikey_ethkey_useslot2", global = true)]
    pub yubikey_ethkey_useslot2: bool,
    
    /// Salt Phrase for YubiKey Slot 2 Ethereum Key Derivation
    #[arg(long = "yubikey_ethkey_salt", global = true)]
    pub yubikey_ethkey_salt: Option<String>,
    
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generates pub_key.pem and priv_key.pem
    Keygen {
        /// Passphrase to lock the private key (optional, will prompt if omitted)
        #[arg(long = "pass")]
        pass: Option<String>,
        /// Do not embed standard PEM headers for maximum stealth plausible deniability
        #[arg(long = "nopemhead")]
        nopemhead: bool,
        /// PNG Carrier to inject the private key into (Steganography)
        #[arg(long = "stego")]
        stego: Option<PathBuf>,
        /// Hardware Token Only (Passphrase Replacement)
        #[arg(long = "yubikey", conflicts_with = "yubikey_and_pass")]
        yubikey: bool,
        /// Hardware Token + Passphrase required (Extreme OPSEC)
        #[arg(long = "yubikey_and_pass", conflicts_with = "yubikey")]
        yubikey_and_pass: bool,
    },
    /// Generates a new Ethereum Private Key for Irys Upload Signing
    KeygenEth {
        /// Optional output path for the generated ethereum key
        #[arg(long = "tgt_loc")]
        tgt_loc: Option<PathBuf>,
        
        /// Enable deterministic derivation (requires --salt and either --passphrase or --yubikey)
        #[arg(long = "deterministic")]
        deterministic: bool,
        
        /// Custom salt phrase for deterministic derivation
        #[arg(long = "salt", required_if_eq("deterministic", "true"))]
        salt: Option<String>,
        
        /// Passphrase for deterministic derivation (min 16 chars)
        #[arg(long = "passphrase", conflicts_with = "yubikey")]
        passphrase: Option<String>,
        
        /// Hardware Token (YubiKey Slot 2) for deterministic derivation
        #[arg(long = "yubikey", conflicts_with = "passphrase")]
        yubikey: bool,
    },
    /// Test Irys Deep Hash Upload
    TestIrys {
        file: String,
    },
    /// Encrypts a file using pub_key.pem
    Encrypt {
        /// Legacy positional file argument (acts exactly like --src_loc)
        #[arg(conflicts_with_all = ["src_net", "src_loc", "src_ipfs"])]
        file: Option<PathBuf>,
        
        /// Network URL for the payload to encrypt
        #[arg(long = "src_net", required_unless_present_any = ["src_loc", "src_ipfs", "file"], conflicts_with_all = ["src_loc", "src_ipfs", "file"])]
        src_net: Option<String>,
        /// Local file path for the payload to encrypt
        #[arg(long = "src_loc", required_unless_present_any = ["src_net", "src_ipfs", "file"], conflicts_with_all = ["src_net", "src_ipfs", "file"])]
        src_loc: Option<PathBuf>,
        /// IPFS CID for the payload to encrypt
        #[arg(long = "src_ipfs", required_unless_present_any = ["src_net", "src_loc", "file"], conflicts_with_all = ["src_net", "src_loc", "file"])]
        src_ipfs: Option<String>,
        
        /// Network URL for the public key
        #[arg(long = "pubkey_net", conflicts_with_all = ["pubkey_loc", "pubkey_ipfs"])]
        pubkey_net: Option<String>,
        /// Local file path for the public key
        #[arg(long = "pubkey_loc", conflicts_with_all = ["pubkey_net", "pubkey_ipfs"])]
        pubkey_loc: Option<PathBuf>,
        /// IPFS CID for the public key
        #[arg(long = "pubkey_ipfs", conflicts_with_all = ["pubkey_net", "pubkey_loc"])]
        pubkey_ipfs: Option<String>,
        
        /// Output file path for the encrypted archive (optional)
        #[arg(long = "tgt_loc")]
        tgt_loc: Option<PathBuf>,
    },
    /// Decrypts a file using priv_key.pem
    Decrypt {
        /// Legacy positional file argument (acts exactly like --src_loc)
        #[arg(conflicts_with_all = ["src_net", "src_loc", "src_ipfs"])]
        file: Option<std::path::PathBuf>,
        
        /// Network URL for the encrypted payload
        #[arg(long = "src_net", required_unless_present_any = ["src_loc", "src_ipfs", "file"], conflicts_with_all = ["src_loc", "src_ipfs", "file"])]
        src_net: Option<String>,
        /// Local file path for the encrypted payload
        #[arg(long = "src_loc", required_unless_present_any = ["src_net", "src_ipfs", "file"], conflicts_with_all = ["src_net", "src_ipfs", "file"])]
        src_loc: Option<std::path::PathBuf>,
        /// IPFS CID for the encrypted payload
        #[arg(long = "src_ipfs", required_unless_present_any = ["src_net", "src_loc", "file"], conflicts_with_all = ["src_net", "src_loc", "file"])]
        src_ipfs: Option<String>,
        
        /// Network URL for the private key
        #[arg(long = "privkey_net", conflicts_with_all = ["privkey_loc", "privkey_ipfs"])]
        privkey_net: Option<String>,
        /// Local file path for the private key
        #[arg(long = "privkey_loc", conflicts_with_all = ["privkey_net", "privkey_ipfs"])]
        privkey_loc: Option<std::path::PathBuf>,
        /// IPFS CID for the private key
        #[arg(long = "privkey_ipfs", conflicts_with_all = ["privkey_net", "privkey_loc"])]
        privkey_ipfs: Option<String>,
        
        /// Output file path for the decrypted file (optional)
        #[arg(long = "tgt_loc")]
        tgt_loc: Option<std::path::PathBuf>,
        /// Passphrase to decrypt the private key (optional, will prompt if omitted)
        #[arg(long = "pass")]
        pass: Option<String>,
        /// Flag to indicate the privkey_loc is a PNG carrier (Steganography)
        #[arg(long = "stego")]
        stego: bool,
        /// Hardware Token Only (Passphrase Replacement)
        #[arg(long = "yubikey", conflicts_with = "yubikey_and_pass")]
        yubikey: bool,
        /// Hardware Token + Passphrase required (Extreme OPSEC)
        #[arg(long = "yubikey_and_pass", conflicts_with = "yubikey")]
        yubikey_and_pass: bool,
    },
    /// Scans an encrypted file for structural corruption or regenerates a public key
    Forensic {
        /// Encrypted file to scan (required unless --keygen_pub is used)
        #[arg(required_unless_present = "keygen_pub")]
        file: Option<PathBuf>,
        
        /// Trigger public key regeneration mode
        #[arg(long = "keygen_pub", conflicts_with = "file")]
        keygen_pub: bool,
        
        /// Network URL for the private key
        #[arg(long = "privkey_net", conflicts_with_all = ["privkey_loc", "privkey_ipfs", "file"])]
        privkey_net: Option<String>,
        
        /// Local file path for the private key
        #[arg(long = "privkey_loc", conflicts_with_all = ["privkey_net", "privkey_ipfs", "file"])]
        privkey_loc: Option<PathBuf>,
        
        /// IPFS CID for the private key
        #[arg(long = "privkey_ipfs", conflicts_with_all = ["privkey_net", "privkey_loc", "file"])]
        privkey_ipfs: Option<String>,
        
        /// Output path for the regenerated public key
        #[arg(long = "tgt_loc")]
        tgt_loc: Option<PathBuf>,
        
        /// Passphrase to unlock the private key (optional, will prompt if omitted)
        #[arg(long = "pass")]
        pass: Option<String>,
        
        /// Hardware Token Only
        #[arg(long = "yubikey", conflicts_with = "yubikey_and_pass")]
        yubikey: bool,
        
        /// Hardware Token + Passphrase required
        #[arg(long = "yubikey_and_pass", conflicts_with = "yubikey")]
        yubikey_and_pass: bool,
        
        /// Whether the private key is embedded in a stego carrier
        #[arg(long = "stego")]
        stego: bool,
        
        /// Generate headerless Stealth Keys
        #[arg(long = "nopemhead")]
        nopemhead: bool,
    },
    /// Launch the graphical user interface (GUI)
    Gui,
    /// Post-Generation Steganography Manipulation
    Stego {
        /// Inject private key into a carrier
        #[arg(long = "inject", conflicts_with = "extract")]
        inject: bool,
        
        /// Extract private key from a carrier
        #[arg(long = "extract", conflicts_with = "inject")]
        extract: bool,

        /// The carrier image path (target for inject)
        #[arg(long = "tgt_loc")]
        tgt_loc: Option<PathBuf>,

        /// The stego image path (source for extract)
        #[arg(long = "src_loc")]
        src_loc: Option<PathBuf>,

        /// The private key path (input for inject, output for extract)
        #[arg(long = "privkey_loc")]
        privkey_loc: Option<PathBuf>,
    },
    /// Hardware Token (YubiKey) Provisioning Tools
    Yubikey {
        /// Generate a deterministic 20-byte HMAC-SHA1 hex secret from a passphrase
        #[arg(long = "genhmacsha1")]
        genhmacsha1: bool,
        
        /// Passphrase to derive the secret from (optional, will prompt if omitted)
        #[arg(long = "pass")]
        pass: Option<String>,
        
        /// Output file path for the derived 40-character hex string (optional)
        #[arg(long = "tgt_loc")]
        tgt_loc: Option<PathBuf>,
        
        /// Inject secret directly to YubiKey Slot 2 over PC/SC (Zero-Disk)
        #[arg(long = "yubikey_direct")]
        yubikey_direct: bool,
        
        /// Inject secret directly to YubiKey Slot 2 and require physical touch (-t)
        #[arg(long = "yubikey_direct_touch")]
        yubikey_direct_touch: bool,
    },
}
