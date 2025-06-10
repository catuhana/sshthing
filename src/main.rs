use std::io::Write as _;

use clap::Parser as _;
use rand::{Rng, SeedableRng as _};
use rand_chacha::ChaCha12Rng;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use crate::errors::SshThingError;
use crate::keep_awake::KeepAwake as _;

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

    let mut keep_awake = if !cli.no_keep_awake {
        Some(keep_awake::SystemKeepAwake::new(
            "sshthing is generating keys",
        )?)
    } else {
        None
    };
    if let Some(ref mut ka) = keep_awake {
        ka.prevent_sleep()?;
    }

    let generated_keys_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let should_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (key_tx, key_rx) = std::sync::mpsc::channel::<key::Ed25519Key>();

    let generator_handles: Vec<_> = (0..cli.threads)
        .map(|_| {
            let handle_counter = std::sync::Arc::clone(&generated_keys_counter);
            let handle_key_tx = key_tx.clone();
            let handle_should_stop = std::sync::Arc::clone(&should_stop);

            let keywords = cli.keywords.clone();
            let search_fields = search_fields.clone();
            let search_all_keywords = cli.requires_all_keywords();
            let search_all_fields = cli.requires_all_fields();

            std::thread::spawn(move || {
                let mut thread_rng = ChaCha12Rng::from_os_rng();

                while !handle_should_stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let generated_key =
                        key::Ed25519Key::new_from_secret_key(thread_rng.random::<[u8; 32]>());
                    handle_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    if generated_key.matches_search(
                        &keywords,
                        &search_fields,
                        search_all_keywords,
                        search_all_fields,
                    ) {
                        let _ = handle_key_tx.send(generated_key);
                        break;
                    }
                }
            })
        })
        .collect();
    std::mem::drop(key_tx);

    let status_counter = std::sync::Arc::clone(&generated_keys_counter);
    let status_should_stop = std::sync::Arc::clone(&should_stop);
    let status_handle = std::thread::spawn(move || {
        let mut last_count = 0;
        let mut last_instant = std::time::Instant::now();

        let start_instant = last_instant;

        while !status_should_stop.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_secs(1));

            let current_count = status_counter.load(std::sync::atomic::Ordering::Relaxed);
            let current_instant = std::time::Instant::now();
            let elapsed = current_instant.duration_since(last_instant).as_secs_f64();
            let total_elapsed = current_instant.duration_since(start_instant).as_secs_f64();

            let generated_keys_per_second = (current_count - last_count) as f64 / elapsed;
            let average_keys_per_second = current_count as f64 / total_elapsed;

            print!(
                "\rGenerated keys: {current_count} ({generated_keys_per_second:.2} keys/s, avg: {average_keys_per_second:.2} keys/s)"
            );
            let _ = std::io::stdout().flush();

            last_count = current_count;
            last_instant = current_instant;
        }
    });

    if let Ok(found_key) = key_rx.recv() {
        println!(
            "\nMatching key found after generating {} keys!",
            generated_keys_counter.load(std::sync::atomic::Ordering::Relaxed)
        );

        println!(
            "SHA256 fingerprint: {}",
            found_key.get_key_info().sha256_fingerprint
        );
        println!(
            "SHA512 fingerprint: {}",
            found_key.get_key_info().sha512_fingerprint
        );

        std::fs::create_dir_all("generated").map_err(SshThingError::Io)?;
        found_key.write_openssh_public(&mut std::fs::File::create("generated/id_ed25519.pub")?)?;
        found_key.write_openssh_private(&mut std::fs::File::create("generated/id_ed25519")?)?;

        println!("Saved private and public keys to 'generated' directory.");
    } else {
        println!(
            "\nNo matching key found after generating {} keys.",
            generated_keys_counter.load(std::sync::atomic::Ordering::Relaxed)
        );
    }
    should_stop.store(true, std::sync::atomic::Ordering::Relaxed);

    for generator in generator_handles {
        let _ = generator.join();
    }
    let _ = status_handle.join();

    println!("\nKey generation completed.");

    Ok(())
}
