#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

use std::io::Write as _;

use clap::Parser as _;
use rand::{Rng, SeedableRng as _};
use rand_chacha::ChaCha12Rng;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use crate::errors::SshThingError;
use crate::keep_awake::KeepAwake as _;
use crate::key::OpenSSHFormatter;
use crate::key::SSHWireFormatter;
use crate::key::ed25519::Ed25519Key;

mod cli;
mod errors;
mod keep_awake;
mod key;

fn main() -> Result<(), SshThingError> {
    let cli = cli::Cli::parse();

    let search_fields = cli.search_fields();
    println!("=== SSHThing Options ===");
    println!("Keywords: {:?}", cli.keywords);
    println!("Thread count: {}", cli.threads);
    println!("Keep awake: {}", !cli.no_keep_awake);
    println!("Match requirements:");
    println!("  - All keywords required: {}", cli.requires_all_keywords());
    println!("  - All fields required: {}", cli.requires_all_fields());
    println!("Search mode:");
    if cli.all {
        println!("  - Searching ALL fields");
    } else if cli.keys_only {
        println!("  - Searching KEYS ONLY (private-key, public-key)");
    } else if cli.fingerprints_only {
        println!("  - Searching FINGERPRINTS ONLY (sha256, sha512)");
    } else {
        println!("  - Searching CUSTOM fields: {search_fields:?}");
    }
    println!("========================");
    println!("Starting SSH key generation...");

    let mut keep_awake = if cli.no_keep_awake {
        None
    } else {
        Some(keep_awake::SystemKeepAwake::new(
            "sshthing is generating keys",
        )?)
    };
    if let Some(ref mut ka) = keep_awake {
        ka.prevent_sleep()?;
    }

    let generated_keys_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (key_tx, key_rx) = std::sync::mpsc::channel::<key::ed25519::Ed25519Key>();

    let search_engine = std::sync::Arc::new(cli.search_engine());

    let generator_handles: Vec<_> = (0..cli.threads)
        .map(|index| {
            let handle_counter = std::sync::Arc::clone(&generated_keys_counter);
            let handle_key_tx = key_tx.clone();

            let search_engine = std::sync::Arc::clone(&search_engine);

            std::thread::Builder::new()
                .name(format!("generator-{index}"))
                .spawn(move || {
                    let mut thread_rng = ChaCha12Rng::from_os_rng();
                    let mut secret_key_buffer = [0u8; 32];

                    loop {
                        thread_rng.fill(&mut secret_key_buffer);
                        let generated_key =
                            key::ed25519::Ed25519Key::new_from_secret_key(&secret_key_buffer);

                        handle_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                        if search_engine.search_matches(&generated_key) {
                            let _ = handle_key_tx.send(generated_key);
                            break;
                        }
                    }
                })
        })
        .collect();

    drop(key_tx);

    let mut last_count = 0;
    let mut last_instant = std::time::Instant::now();
    let start_instant = last_instant;

    let found_key = loop {
        match key_rx.recv_timeout(std::time::Duration::from_millis(300)) {
            Ok(found_key) => {
                break Some(found_key);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                break None;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let current_count =
                    generated_keys_counter.load(std::sync::atomic::Ordering::Relaxed);
                let current_instant = std::time::Instant::now();

                let elapsed = current_instant.duration_since(last_instant).as_secs_f64();
                let total_elapsed = current_instant.duration_since(start_instant).as_secs_f64();

                let generated_keys_per_second = (current_count - last_count) as f64 / elapsed;
                let average_keys_per_second = current_count as f64 / total_elapsed;

                print!("\r\x1b[K");
                print!(
                    "Generated keys: {current_count} ({generated_keys_per_second:.2} keys/s, avg: {average_keys_per_second:.2} keys/s)"
                );
                let _ = std::io::stdout().flush();

                last_count = current_count;
                last_instant = current_instant;
            }
        }
    };

    if let Some(found_key) = found_key {
        println!(
            "\n\nMatching key found after generating {} keys!",
            generated_keys_counter.load(std::sync::atomic::Ordering::Relaxed)
        );

        println!(
            "SHA256 fingerprint: {}",
            Ed25519Key::get_sha256_fingerprint(&found_key.verifying_key)
        );
        println!(
            "SHA512 fingerprint: {}",
            Ed25519Key::get_sha512_fingerprint(&found_key.verifying_key)
        );

        std::fs::create_dir_all("generated")?;
        std::fs::write(
            "generated/id_ed25519.pub",
            Ed25519Key::format_public_key(&found_key.verifying_key),
        )?;
        std::fs::write(
            "generated/id_ed25519",
            Ed25519Key::format_private_key(&found_key.signing_key, &found_key.verifying_key),
        )?;
        // found_key.write_openssh_public(&mut std::fs::File::create("generated/id_ed25519.pub")?)?;
        // found_key.write_openssh_private(&mut std::fs::File::create("generated/id_ed25519")?)?;

        println!("Saved private and public keys to 'generated' directory.");
    } else {
        println!(
            "\n\nNo matching key found after generating {} keys.",
            generated_keys_counter.load(std::sync::atomic::Ordering::Relaxed)
        );
    }

    for generator in generator_handles {
        let _ = generator?.join();
    }

    println!("\nKey generation completed.");

    Ok(())
}
