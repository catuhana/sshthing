use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use clap::Parser as _;
use cli::{HashType, MatchMode, SearchField, SearchIn};
use rand_chacha::ChaCha8Rng;
use ssh_key::rand_core::CryptoRngCore;
use ssh_key::{rand_core::SeedableRng as _, Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey};

mod cli;

#[derive(Debug)]
struct FoundKey {
    private: PrivateKey,
    public: PublicKey,
    keywords: Vec<String>,
    in_fields: SearchIn,
}

#[derive(Debug)]
struct KeyGenerator {
    generators: Vec<GeneratorThread>,

    keywords: Arc<Vec<String>>,
    search_in: SearchIn,
    match_mode: MatchMode,

    start_time: Arc<Option<Instant>>,
}

#[derive(Debug)]
struct GeneratorThread {
    handle: JoinHandle<()>,
    checked_keys: Arc<AtomicU64>,
    found_key: Arc<Mutex<Option<FoundKey>>>,
}

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();

    println!("Starting key generation with {} threads", cli.threads);
    println!(
        "Searching for keywords: {:?} in {:?} with match mode {:?}",
        cli.keywords, cli.search_in, cli.match_mode
    );

    KeyGenerator::new(cli.keywords, cli.search_in, cli.match_mode).run(cli.threads)?;

    Ok(())
}

impl KeyGenerator {
    fn new(keywords: Vec<String>, search_in: SearchIn, match_mode: MatchMode) -> Self {
        Self {
            generators: Vec::new(),
            keywords: Arc::new(keywords),
            search_in,
            match_mode,
            start_time: Arc::new(None),
        }
    }

    fn run(&mut self, thread_count: usize) -> anyhow::Result<()> {
        let stop_flag = Arc::new(AtomicBool::new(false));
        self.spawn_threads(thread_count, &stop_flag);

        self.monitor_progress(&stop_flag);

        for (idx, generator) in self.generators.drain(..).enumerate() {
            generator.handle.join().unwrap();

            if let Some(found_key) = generator.found_key.lock().unwrap().as_ref() {
                println!(
                    "Thread {} found keywords: {:?} in: {:?}",
                    idx, found_key.keywords, found_key.in_fields
                );

                found_key.save(idx)?;
            }
        }

        Ok(())
    }

    fn spawn_threads(&mut self, thread_count: usize, stop_flag: &Arc<AtomicBool>) {
        let mut generators = Vec::new();

        for thread_index in 0..thread_count {
            let stop_flag = Arc::clone(stop_flag);
            let keywords = self.keywords.clone();

            let search_in = self.search_in.clone();
            let match_mode = self.match_mode.clone();

            let checked_keys = Arc::new(AtomicU64::new(0));
            let found_key = Arc::new(Mutex::new(None::<FoundKey>));

            let thread_checked_keys = Arc::clone(&checked_keys);
            let thread_found_key = Arc::clone(&found_key);

            let handle = thread::spawn(move || {
                Self::generate_keys(
                    thread_index,
                    &stop_flag,
                    &keywords,
                    &search_in,
                    &match_mode,
                    &thread_checked_keys,
                    &thread_found_key,
                );
            });

            generators.push(GeneratorThread {
                handle,
                checked_keys: Arc::clone(&checked_keys),
                found_key,
            });
        }

        self.generators = generators;
        self.start_time = Arc::new(Some(Instant::now()));
    }

    fn monitor_progress(&self, stop_flag: &Arc<AtomicBool>) {
        let mut last_status_print = Instant::now();

        while !stop_flag.load(Ordering::Relaxed) {
            if last_status_print.elapsed() >= Duration::from_secs(1) {
                let total_keys: u64 = self
                    .generators
                    .iter()
                    .map(|g| g.checked_keys.load(Ordering::Relaxed))
                    .sum();

                let elapsed = self.start_time.as_ref().unwrap().elapsed().as_secs();
                let keys_per_sec = total_keys / elapsed;

                println!("Checked {total_keys} keys total ({keys_per_sec:.2} keys/sec)",);
                last_status_print = Instant::now();
            }
        }
    }

    fn generate_keys(
        thread_index: usize,
        stop_flag: &Arc<AtomicBool>,
        keywords: &[String],
        search_in: &SearchIn,
        match_mode: &MatchMode,
        checked_keys: &AtomicU64,
        found_key: &Arc<Mutex<Option<FoundKey>>>,
    ) {
        let mut rng = ChaCha8Rng::from_seed([u8::try_from(thread_index).unwrap(); 32]);

        while !stop_flag.load(Ordering::Relaxed) {
            if let Some(key) =
                Self::try_generate_matching_key(&mut rng, keywords, search_in, match_mode)
            {
                if let Ok(mut found) = found_key.lock() {
                    *found = Some(key);
                }
                stop_flag.store(true, Ordering::Relaxed);
            }

            checked_keys.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn try_generate_matching_key(
        rng: &mut impl CryptoRngCore,
        keywords: &[String],
        search_in: &SearchIn,
        match_mode: &MatchMode,
    ) -> Option<FoundKey> {
        let private_key = PrivateKey::random(rng, Algorithm::Ed25519).ok()?;
        let public_key = private_key.public_key();

        let key_data = KeyData::new(&private_key, public_key)?;

        if let Some((matched_keywords, matched_in_fields)) =
            key_data.matches(keywords, search_in, match_mode)
        {
            Some(FoundKey {
                private: private_key.clone(),
                public: public_key.clone(),
                keywords: matched_keywords,
                in_fields: matched_in_fields,
            })
        } else {
            None
        }
    }
}

struct KeyData {
    private_openssh: String,
    public_openssh: String,
    sha256_fingerprint: String,
    sha512_fingerprint: String,
}

impl KeyData {
    fn new(private_key: &PrivateKey, public_key: &PublicKey) -> Option<Self> {
        Some(Self {
            private_openssh: private_key.to_openssh(LineEnding::LF).ok()?.to_string(),
            public_openssh: public_key.to_openssh().ok()?,
            sha256_fingerprint: public_key.fingerprint(HashAlg::Sha256).to_string(),
            sha512_fingerprint: public_key.fingerprint(HashAlg::Sha512).to_string(),
        })
    }

    // TODO: There's a bug here. Even though `SearchIn::All` and
    // `MatchMode::All` is passed, it stops as soon as finds a
    // keyword on one of the `SearchIn` enum values.
    fn matches(
        &self,
        keywords: &[String],
        search_in: &SearchIn,
        match_mode: &MatchMode,
    ) -> Option<(Vec<String>, SearchIn)> {
        let searchable_fields = match search_in {
            SearchIn::Specific(fields) => fields
                .iter()
                .map(|field| self.get_field(field))
                .collect::<Vec<_>>(),
            SearchIn::Keys => vec![&self.private_openssh, &self.public_openssh],
            SearchIn::Fingerprints => vec![&self.sha256_fingerprint, &self.sha512_fingerprint],
            SearchIn::All => vec![
                &self.private_openssh,
                &self.public_openssh,
                &self.sha256_fingerprint,
                &self.sha512_fingerprint,
            ],
        };

        let mut matched_keywords = Vec::new();
        let mut found_in_private = false;
        let mut found_in_public = false;
        let mut found_in_sha256 = false;
        let mut found_in_sha512 = false;

        let matches = match match_mode {
            MatchMode::All => keywords.iter().all(|keyword| {
                let mut found = false;

                for (idx, field) in searchable_fields.iter().enumerate() {
                    if Self::check_field(field, keyword) {
                        found = true;
                        match search_in {
                            SearchIn::All => match idx {
                                0 => found_in_private = true,
                                1 => found_in_public = true,
                                2 => found_in_sha256 = true,
                                3 => found_in_sha512 = true,
                                _ => {}
                            },
                            SearchIn::Keys => match idx {
                                0 => found_in_private = true,
                                1 => found_in_public = true,
                                _ => {}
                            },
                            SearchIn::Fingerprints => match idx {
                                0 => found_in_sha256 = true,
                                1 => found_in_sha512 = true,
                                _ => {}
                            },
                            SearchIn::Specific(fields) => {
                                if idx < fields.len() {
                                    match &fields[idx] {
                                        SearchField::PrivateKey => found_in_private = true,
                                        SearchField::PublicKey => found_in_public = true,
                                        SearchField::Fingerprint(HashType::Sha256) => {
                                            found_in_sha256 = true;
                                        }
                                        SearchField::Fingerprint(HashType::Sha512) => {
                                            found_in_sha512 = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if found {
                    matched_keywords.push(keyword.clone());
                }
                found
            }),
            MatchMode::Any => keywords.iter().any(|keyword| {
                let mut found = false;

                for (idx, field) in searchable_fields.iter().enumerate() {
                    if Self::check_field(field, keyword) {
                        found = true;

                        match search_in {
                            SearchIn::All => match idx {
                                0 => found_in_private = true,
                                1 => found_in_public = true,
                                2 => found_in_sha256 = true,
                                3 => found_in_sha512 = true,
                                _ => {}
                            },
                            SearchIn::Keys => match idx {
                                0 => found_in_private = true,
                                1 => found_in_public = true,
                                _ => {}
                            },
                            SearchIn::Fingerprints => match idx {
                                0 => found_in_sha256 = true,
                                1 => found_in_sha512 = true,
                                _ => {}
                            },
                            SearchIn::Specific(fields) => {
                                if idx < fields.len() {
                                    match &fields[idx] {
                                        SearchField::PrivateKey => found_in_private = true,
                                        SearchField::PublicKey => found_in_public = true,
                                        SearchField::Fingerprint(HashType::Sha256) => {
                                            found_in_sha256 = true;
                                        }
                                        SearchField::Fingerprint(HashType::Sha512) => {
                                            found_in_sha512 = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if found {
                    matched_keywords.push(keyword.clone());
                }
                found
            }),
        };

        if !matches {
            return None;
        }

        let result_search_in =
            if found_in_private && found_in_public && found_in_sha256 && found_in_sha512 {
                SearchIn::All
            } else if found_in_private && found_in_public {
                SearchIn::Keys
            } else if found_in_sha256 && found_in_sha512 {
                SearchIn::Fingerprints
            } else {
                let mut specific_fields = Vec::new();
                if found_in_private {
                    specific_fields.push(SearchField::PrivateKey);
                }
                if found_in_public {
                    specific_fields.push(SearchField::PublicKey);
                }
                if found_in_sha256 {
                    specific_fields.push(SearchField::Fingerprint(HashType::Sha256));
                }
                if found_in_sha512 {
                    specific_fields.push(SearchField::Fingerprint(HashType::Sha512));
                }
                SearchIn::Specific(specific_fields)
            };

        Some((matched_keywords, result_search_in))
    }

    const fn get_field(&self, field: &SearchField) -> &String {
        match field {
            SearchField::PrivateKey => &self.private_openssh,
            SearchField::PublicKey => &self.public_openssh,
            SearchField::Fingerprint(HashType::Sha256) => &self.sha256_fingerprint,
            SearchField::Fingerprint(HashType::Sha512) => &self.sha512_fingerprint,
        }
    }

    fn check_field(field: &str, keyword: &str) -> bool {
        field.to_lowercase().contains(&keyword.to_lowercase())
    }
}

impl FoundKey {
    fn save(&self, thread_index: usize) -> anyhow::Result<()> {
        let output_dir = PathBuf::from(format!("generated/{thread_index}"));
        fs::create_dir_all(&output_dir)?;

        self.save_private_key(&output_dir.join("private_key.pem"))?;
        self.save_public_key(&output_dir.join("public_key.pub"))?;
        self.save_fingerprints(&output_dir.join("fingerprints.txt"))?;

        Ok(())
    }

    fn save_private_key(&self, path: &Path) -> anyhow::Result<()> {
        let mut file = File::create(path)?;
        file.write_all(self.private.to_openssh(LineEnding::LF)?.as_bytes())?;

        Ok(())
    }

    fn save_public_key(&self, path: &Path) -> anyhow::Result<()> {
        let mut file = File::create(path)?;
        file.write_all(self.public.to_openssh()?.as_bytes())?;

        Ok(())
    }

    fn save_fingerprints(&self, path: &Path) -> anyhow::Result<()> {
        let mut file = File::create(path)?;
        writeln!(file, "{}", self.public.fingerprint(HashAlg::Sha256))?;
        writeln!(file, "{}", self.public.fingerprint(HashAlg::Sha512))?;

        Ok(())
    }
}
