use clap::{Args, Subcommand};
use std::sync::Arc;
use std::path::PathBuf;

use crate::config::AevorConfig;
use crate::error::{AevorError, Result};
use crate::cli::utils::display;
use crate::cli::commands::CommandExecutor;

/// Utility commands for Aevor
#[derive(Debug, Args)]
pub struct UtilsCommand {
    /// The specific utility command to execute
    #[clap(subcommand)]
    pub command: UtilsSubcommand,
}

/// Available utility subcommands
#[derive(Debug, Subcommand)]
pub enum UtilsSubcommand {
    /// Generate a keypair
    #[clap(name = "keygen")]
    KeyGen(KeyGenArgs),
    
    /// Generate a new configuration file
    #[clap(name = "genconfig")]
    GenConfig(GenConfigArgs),
    
    /// Generate a genesis file
    #[clap(name = "genesis")]
    Genesis(GenesisArgs),
    
    /// Check the health of a node
    #[clap(name = "health")]
    Health(HealthArgs),
    
    /// Calculate hash of a file
    #[clap(name = "hash")]
    Hash(HashArgs),
    
    /// Encode/decode base64 data
    #[clap(name = "base64")]
    Base64(Base64Args),
    
    /// Calculate hash of a string
    #[clap(name = "hash-str")]
    HashStr(HashStrArgs),
    
    /// Generate a random seed
    #[clap(name = "seed")]
    Seed(SeedArgs),
    
    /// Version information
    #[clap(name = "version")]
    Version,
}

/// Arguments for key generation
#[derive(Debug, Args)]
pub struct KeyGenArgs {
    /// Output file for the key pair
    #[clap(short, long)]
    pub output: Option<PathBuf>,
    
    /// Only generate the public key
    #[clap(short, long)]
    pub public_only: bool,
    
    /// Algorithm to use (ed25519, secp256k1, bls)
    #[clap(short, long, default_value = "ed25519")]
    pub algorithm: String,
}

/// Arguments for configuration generation
#[derive(Debug, Args)]
pub struct GenConfigArgs {
    /// Output file for the configuration
    #[clap(short, long)]
    pub output: Option<PathBuf>,
    
    /// Use minimal configuration
    #[clap(short, long)]
    pub minimal: bool,
    
    /// Configure as a validator
    #[clap(short, long)]
    pub validator: bool,
}

/// Arguments for genesis file generation
#[derive(Debug, Args)]
pub struct GenesisArgs {
    /// Output file for the genesis file
    #[clap(short, long)]
    pub output: Option<PathBuf>,
    
    /// Initial validator keys (comma-separated)
    #[clap(short, long)]
    pub validators: Option<String>,
    
    /// Chain ID
    #[clap(short, long, default_value = "aevor-testnet-1")]
    pub chain_id: String,
    
    /// Genesis timestamp (Unix timestamp)
    #[clap(short, long)]
    pub timestamp: Option<u64>,
}

/// Arguments for health check
#[derive(Debug, Args)]
pub struct HealthArgs {
    /// Node URL to check
    #[clap(short, long, default_value = "http://localhost:8080")]
    pub url: String,
    
    /// Timeout in seconds
    #[clap(short, long, default_value = "10")]
    pub timeout: u64,
}

/// Arguments for file hashing
#[derive(Debug, Args)]
pub struct HashArgs {
    /// Path to the file to hash
    pub file: PathBuf,
    
    /// Algorithm to use (sha256, sha512, blake3)
    #[clap(short, long, default_value = "sha256")]
    pub algorithm: String,
}

/// Arguments for base64 encoding/decoding
#[derive(Debug, Args)]
pub struct Base64Args {
    /// Data to encode/decode
    pub data: String,
    
    /// Decode instead of encode
    #[clap(short, long)]
    pub decode: bool,
}

/// Arguments for string hashing
#[derive(Debug, Args)]
pub struct HashStrArgs {
    /// String to hash
    pub input: String,
    
    /// Algorithm to use (sha256, sha512, blake3)
    #[clap(short, long, default_value = "sha256")]
    pub algorithm: String,
}

/// Arguments for seed generation
#[derive(Debug, Args)]
pub struct SeedArgs {
    /// Number of words in the seed phrase
    #[clap(short, long, default_value = "24")]
    pub words: usize,
    
    /// Language to use (english, japanese, korean, spanish, chinese_simplified, chinese_traditional, french, italian)
    #[clap(short, long, default_value = "english")]
    pub language: String,
}

#[async_trait::async_trait]
impl CommandExecutor for UtilsCommand {
    async fn execute(&self, config: Arc<AevorConfig>) -> Result<()> {
        match &self.command {
            UtilsSubcommand::KeyGen(args) => execute_key_gen(args, config).await,
            UtilsSubcommand::GenConfig(args) => execute_gen_config(args, config).await,
            UtilsSubcommand::Genesis(args) => execute_genesis(args, config).await,
            UtilsSubcommand::Health(args) => execute_health_check(args, config).await,
            UtilsSubcommand::Hash(args) => execute_hash_file(args, config).await,
            UtilsSubcommand::Base64(args) => execute_base64(args, config).await,
            UtilsSubcommand::HashStr(args) => execute_hash_str(args, config).await,
            UtilsSubcommand::Seed(args) => execute_generate_seed(args, config).await,
            UtilsSubcommand::Version => execute_version(config).await,
        }
    }
}

async fn execute_key_gen(args: &KeyGenArgs, _config: Arc<AevorConfig>) -> Result<()> {
    display::section("Generating Key Pair");
    
    // Check algorithm
    let algorithm = match args.algorithm.to_lowercase().as_str() {
        "ed25519" => "Ed25519",
        "secp256k1" => "Secp256k1",
        "bls" => "BLS",
        _ => return Err(AevorError::validation(format!("Unsupported algorithm: {}", args.algorithm))),
    };
    
    display::info(&format!("Using algorithm: {}", algorithm));
    
    let spinner = display::spinner("Generating keypair...");
    
    // Generate keypair
    let (private_key, public_key) = match algorithm {
        "Ed25519" => {
            // Generate Ed25519 keypair
            use ed25519_dalek::{Keypair, SecretKey};
            use rand::rngs::OsRng;
            
            let secret = SecretKey::generate(&mut OsRng);
            let keypair = Keypair::from(secret);
            
            (keypair.secret.as_bytes().to_vec(), keypair.public.as_bytes().to_vec())
        },
        "Secp256k1" => {
            // Generate Secp256k1 keypair
            use k256::ecdsa::{SigningKey, VerifyingKey};
            use rand::rngs::OsRng;
            
            let signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = VerifyingKey::from(&signing_key);
            
            (signing_key.to_bytes().to_vec(), verifying_key.to_sec1_bytes().to_vec())
        },
        "BLS" => {
            // Generate BLS keypair
            // Note: This is a simplified example. In a real implementation, 
            // you would use a proper BLS library.
            use rand::rngs::OsRng;
            
            let mut private_key = [0u8; 32];
            OsRng.fill_bytes(&mut private_key);
            
            (private_key.to_vec(), vec![0u8; 48]) // Placeholder for BLS public key
        },
        _ => return Err(AevorError::internal("Unsupported algorithm (internal error)")),
    };
    
    spinner.finish_with_message("Keypair generated successfully!");
    
    // Display or save the keypair
    if let Some(output_path) = &args.output {
        use std::fs::File;
        use std::io::Write;
        
        let output_dir = output_path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(output_dir)?;
        
        if args.public_only {
            let mut file = File::create(output_path)?;
            file.write_all(&public_key)?;
            display::success(&format!("Public key saved to {}", output_path.display()));
        } else {
            // Save private key
            let private_path = output_path.with_extension("private");
            let mut file = File::create(&private_path)?;
            file.write_all(&private_key)?;
            display::success(&format!("Private key saved to {}", private_path.display()));
            
            // Save public key
            let public_path = output_path.with_extension("public");
            let mut file = File::create(&public_path)?;
            file.write_all(&public_key)?;
            display::success(&format!("Public key saved to {}", public_path.display()));
        }
    } else {
        display::section("Generated Keys");
        display::info(&format!("Algorithm: {}", algorithm));
        
        if !args.public_only {
            println!("Private Key: {}", hex::encode(&private_key));
        }
        
        println!("Public Key: {}", hex::encode(&public_key));
    }
    
    Ok(())
}

async fn execute_gen_config(args: &GenConfigArgs, _config: Arc<AevorConfig>) -> Result<()> {
    display::section("Generating Configuration");
    
    // Determine the output path
    let output_path = args.output.clone().unwrap_or_else(|| {
        let aevor_dir = crate::cli::utils::get_aevor_dir();
        aevor_dir.join("config.json")
    });
    
    display::info(&format!("Output path: {}", output_path.display()));
    
    // Create a new configuration
    let mut config = AevorConfig::default();
    
    // Modify based on arguments
    if args.minimal {
        // Set minimal configuration options
        config.storage.cache_size_mb = 128;
        config.vm.max_memory_bytes = 64 * 1024 * 1024; // 64 MB
        config.execution.max_parallel_execution = 4;
        config.network.max_peers = 10;
        
        display::info("Using minimal configuration settings");
    }
    
    if args.validator {
        // Set validator configuration options
        config.node.is_validator = true;
        
        // Generate a validator key if needed
        if !config.consensus.validator.key_path.exists() {
            display::info("Generating validator key...");
            
            // Create directory for the key
            let key_dir = config.consensus.validator.key_path.parent().unwrap_or_else(|| Path::new("."));
            std::fs::create_dir_all(key_dir)?;
            
            // Generate Ed25519 keypair for the validator
            use ed25519_dalek::{Keypair, SecretKey};
            use rand::rngs::OsRng;
            use std::fs::File;
            use std::io::Write;
            
            let secret = SecretKey::generate(&mut OsRng);
            let keypair = Keypair::from(secret);
            
            let private_key = keypair.secret.as_bytes();
            
            // Save the validator key
            let mut file = File::create(&config.consensus.validator.key_path)?;
            file.write_all(private_key)?;
            
            display::success(&format!("Validator key saved to {}", config.consensus.validator.key_path.display()));
        }
        
        display::info("Configured as a validator node");
    }
    
    // Create parent directory if needed
    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    
    // Save the configuration
    config.save(&output_path)?;
    
    display::success(&format!("Configuration saved to {}", output_path.display()));
    
    Ok(())
}

async fn execute_genesis(args: &GenesisArgs, _config: Arc<AevorConfig>) -> Result<()> {
    display::section("Generating Genesis File");
    
    // Determine the output path
    let output_path = args.output.clone().unwrap_or_else(|| {
        let aevor_dir = crate::cli::utils::get_aevor_dir();
        aevor_dir.join("genesis.json")
    });
    
    display::info(&format!("Output path: {}", output_path.display()));
    
    // Parse validators
    let validators = if let Some(validator_str) = &args.validators {
        validator_str.split(',')
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>()
    } else {
        Vec::new()
    };
    
    // Get timestamp
    let timestamp = args.timestamp.unwrap_or_else(|| {
        let now = std::time::SystemTime::now();
        let since_epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap();
        since_epoch.as_secs() * 1000 // Milliseconds
    });
    
    // Create genesis data
    let genesis = serde_json::json!({
        "chain_id": args.chain_id,
        "timestamp": timestamp,
        "initial_validators": validators,
        "initial_state": {
            "accounts": [],
            "validator_set": {
                "validators": validators.iter().map(|validator| {
                    serde_json::json!({
                        "address": validator,
                        "power": 1,
                        "name": format!("validator-{}", validator.chars().take(8).collect::<String>())
                    })
                }).collect::<Vec<_>>()
            }
        },
        "consensus_params": {
            "block": {
                "max_bytes": 2 * 1024 * 1024, // 2 MB
                "max_gas": 10_000_000,
            }
        }
    });
    
    // Create parent directory if needed
    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    
    // Save the genesis file
    std::fs::write(
        &output_path,
        serde_json::to_string_pretty(&genesis).map_err(|e| AevorError::serialization(e.to_string()))?,
    )?;
    
    display::success(&format!("Genesis file saved to {}", output_path.display()));
    
    if validators.is_empty() {
        display::warning("No validators specified. You may want to add validators to the genesis file.");
    } else {
        display::info(&format!("Added {} validators to the genesis file", validators.len()));
    }
    
    Ok(())
}

async fn execute_health_check(args: &HealthArgs, _config: Arc<AevorConfig>) -> Result<()> {
    display::section("Node Health Check");
    
    display::info(&format!("Checking node health at {}", args.url));
    
    // Create a client with timeout
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(args.timeout))
        .build()
        .map_err(|e| AevorError::network(format!("Failed to create HTTP client: {}", e)))?;
    
    // Make a request to the health endpoint
    let spinner = display::spinner("Connecting to node...");
    
    let health_url = format!("{}/health", args.url.trim_end_matches('/'));
    let response = client.get(&health_url)
        .send()
        .await
        .map_err(|e| AevorError::network(format!("Failed to connect to node: {}", e)))?;
    
    // Check the response
    if response.status().is_success() {
        spinner.finish_with_message("Node is healthy!");
        
        // Parse the response
        let health_json = response.json::<serde_json::Value>().await
            .map_err(|e| AevorError::deserialization(format!("Failed to parse response: {}", e)))?;
        
        // Display node information
        if let Some(node_info) = health_json.get("node_info") {
            display::section("Node Information");
            
            if let Some(id) = node_info.get("id").and_then(|v| v.as_str()) {
                display::info(&format!("Node ID: {}", id));
            }
            
            if let Some(version) = node_info.get("version").and_then(|v| v.as_str()) {
                display::info(&format!("Version: {}", version));
            }
            
            if let Some(network) = node_info.get("network").and_then(|v| v.as_str()) {
                display::info(&format!("Network: {}", network));
            }
        }
        
        // Display sync status
        if let Some(sync_info) = health_json.get("sync_info") {
            display::section("Sync Information");
            
            if let Some(syncing) = sync_info.get("syncing").and_then(|v| v.as_bool()) {
                display::info(&format!("Syncing: {}", syncing));
            }
            
            if let Some(latest_block_height) = sync_info.get("latest_block_height").and_then(|v| v.as_u64()) {
                display::info(&format!("Latest Block Height: {}", latest_block_height));
            }
            
            if let Some(latest_block_time) = sync_info.get("latest_block_time").and_then(|v| v.as_str()) {
                display::info(&format!("Latest Block Time: {}", latest_block_time));
            }
        }
        
        // Display validator info
        if let Some(validator_info) = health_json.get("validator_info") {
            display::section("Validator Information");
            
            if let Some(address) = validator_info.get("address").and_then(|v| v.as_str()) {
                display::info(&format!("Validator Address: {}", address));
            }
            
            if let Some(voting_power) = validator_info.get("voting_power").and_then(|v| v.as_u64()) {
                display::info(&format!("Voting Power: {}", voting_power));
            }
        }
    } else {
        spinner.finish_with_message("Node is unhealthy!");
        
        display::error(&format!(
            "Health check failed with status code: {}",
            response.status()
        ));
        
        // Try to get error details
        let error_text = response.text().await
            .unwrap_or_else(|_| "Unknown error".to_string());
        
        display::error(&format!("Error details: {}", error_text));
    }
    
    Ok(())
}

async fn execute_hash_file(args: &HashArgs, _config: Arc<AevorConfig>) -> Result<()> {
    display::section("File Hash Calculation");
    
    // Check if file exists
    if !args.file.exists() {
        return Err(AevorError::validation(format!("File not found: {}", args.file.display())));
    }
    
    display::info(&format!("Hashing file: {}", args.file.display()));
    display::info(&format!("Using algorithm: {}", args.algorithm));
    
    // Read file
    let file_data = std::fs::read(&args.file)
        .map_err(|e| AevorError::io(e))?;
    
    // Calculate hash
    let hash = match args.algorithm.to_lowercase().as_str() {
        "sha256" => {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&file_data);
            hex::encode(hasher.finalize())
        },
        "sha512" => {
            use sha2::{Sha512, Digest};
            let mut hasher = Sha512::new();
            hasher.update(&file_data);
            hex::encode(hasher.finalize())
        },
        "blake3" => {
            let hash = blake3::hash(&file_data);
            hex::encode(hash.as_bytes())
        },
        _ => return Err(AevorError::validation(format!("Unsupported algorithm: {}", args.algorithm))),
    };
    
    display::section("Hash Result");
    println!("{}", hash);
    
    Ok(())
}

async fn execute_base64(args: &Base64Args, _config: Arc<AevorConfig>) -> Result<()> {
    display::section("Base64 Encoding/Decoding");
    
    let result = if args.decode {
        display::info("Decoding base64 data");
        
        let bytes = base64::decode(&args.data)
            .map_err(|e| AevorError::validation(format!("Invalid base64 data: {}", e)))?;
        
        match String::from_utf8(bytes.clone()) {
            Ok(s) => s,
            Err(_) => format!("(Binary data, {} bytes): {}", bytes.len(), hex::encode(&bytes)),
        }
    } else {
        display::info("Encoding data to base64");
        base64::encode(&args.data)
    };
    
    display::section("Result");
    println!("{}", result);
    
    Ok(())
}

async fn execute_hash_str(args: &HashStrArgs, _config: Arc<AevorConfig>) -> Result<()> {
    display::section("String Hash Calculation");
    
    display::info(&format!("Hashing string: {}", args.input));
    display::info(&format!("Using algorithm: {}", args.algorithm));
    
    // Calculate hash
    let hash = match args.algorithm.to_lowercase().as_str() {
        "sha256" => {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(args.input.as_bytes());
            hex::encode(hasher.finalize())
        },
        "sha512" => {
            use sha2::{Sha512, Digest};
            let mut hasher = Sha512::new();
            hasher.update(args.input.as_bytes());
            hex::encode(hasher.finalize())
        },
        "blake3" => {
            let hash = blake3::hash(args.input.as_bytes());
            hex::encode(hash.as_bytes())
        },
        _ => return Err(AevorError::validation(format!("Unsupported algorithm: {}", args.algorithm))),
    };
    
    display::section("Hash Result");
    println!("{}", hash);
    
    Ok(())
}

async fn execute_generate_seed(args: &SeedArgs, _config: Arc<AevorConfig>) -> Result<()> {
    display::section("Seed Phrase Generation");
    
    // Check word count
    if args.words != 12 && args.words != 15 && args.words != 18 && args.words != 21 && args.words != 24 {
        return Err(AevorError::validation("Word count must be 12, 15, 18, 21, or 24"));
    }
    
    display::info(&format!("Generating {} word seed phrase", args.words));
    display::info(&format!("Language: {}", args.language));
    
    // Generate random entropy
    let entropy_bytes = match args.words {
        12 => 16, // 128 bits
        15 => 20, // 160 bits
        18 => 24, // 192 bits
        21 => 28, // 224 bits
        24 => 32, // 256 bits
        _ => return Err(AevorError::validation("Invalid word count")),
    };
    
    use rand::{rngs::OsRng, RngCore};
    let mut entropy = vec![0u8; entropy_bytes];
    OsRng.fill_bytes(&mut entropy);
    
    // This is a placeholder for actual BIP-39 implementation
    // In a real implementation, you would use a proper BIP-39 library
    let seed_phrase = generate_placeholder_seed_phrase(args.words);
    
    display::section("Generated Seed Phrase");
    println!("{}", seed_phrase);
    
    display::warning("IMPORTANT: Keep this seed phrase safe and private.");
    display::warning("Anyone with access to this seed phrase can control your assets.");
    
    Ok(())
}

async fn execute_version(_config: Arc<AevorConfig>) -> Result<()> {
    display::section("Aevor Version Information");
    
    println!("Version: {}", crate::VERSION);
    println!("Build Date: {}", env!("CARGO_PKG_VERSION"));
    println!("Commit: {}", option_env!("GIT_COMMIT").unwrap_or("unknown"));
    println!("Platform: {}", std::env::consts::OS);
    println!("Architecture: {}", std::env::consts::ARCH);
    
    Ok(())
}

// Helper function to generate a placeholder seed phrase
fn generate_placeholder_seed_phrase(word_count: usize) -> String {
    // This is a placeholder - in a real implementation, you would use a proper BIP-39 library
    let example_words = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
        "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
        "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
        "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
        // ... more words would be here in a real implementation
    ];
    
    use rand::{seq::SliceRandom, thread_rng};
    let mut rng = thread_rng();
    
    (0..word_count)
        .map(|_| example_words.choose(&mut rng).unwrap())
        .collect::<Vec<&str>>()
        .join(" ")
}
