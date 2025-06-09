#[derive(clap::Parser, Debug)]
pub struct Cli {
    /// The keywords to search for in SSH fields
    #[arg(value_delimiter = ',', required = true)]
    pub keywords: Vec<String>,

    /// SSH fields to search in (default: sha256-fingerprint)
    #[arg(long, short = 'f', value_delimiter = ',', default_values = ["sha256-fingerprint"])]
    pub fields: Vec<SearchField>,

    /// Require ALL keywords to match (default: any keyword matches)
    #[arg(long)]
    pub all_keywords: bool,

    /// Require ALL fields to match (default: any field matches)
    #[arg(long)]
    pub all_fields: bool,

    /// Number of threads to use
    #[arg(long, short, default_value_t = num_cpus::get())]
    pub threads: usize,

    /// Search in all available fields
    #[arg(long, conflicts_with = "fields")]
    pub all: bool,

    /// Search only in key fields (private-key, public-key)
    #[arg(long, conflicts_with_all = ["fields", "all"])]
    pub keys_only: bool,

    /// Search only in fingerprint fields (sha256, sha512)
    #[arg(long, conflicts_with_all = ["fields", "all", "keys_only"])]
    pub fingerprints_only: bool,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum SearchField {
    #[value(name = "private-key")]
    PrivateKey,
    #[value(name = "public-key")]
    PublicKey,
    #[value(name = "sha256-fingerprint")]
    Sha256Fingerprint,
    #[value(name = "sha512-fingerprint")]
    Sha512Fingerprint,
}

impl Cli {
    pub fn search_fields(&self) -> Vec<SearchField> {
        if self.all {
            vec![
                SearchField::PrivateKey,
                SearchField::PublicKey,
                SearchField::Sha256Fingerprint,
                SearchField::Sha512Fingerprint,
            ]
        } else if self.keys_only {
            vec![SearchField::PrivateKey, SearchField::PublicKey]
        } else if self.fingerprints_only {
            vec![
                SearchField::Sha256Fingerprint,
                SearchField::Sha512Fingerprint,
            ]
        } else {
            self.fields.clone()
        }
    }

    pub const fn requires_all_keywords(&self) -> bool {
        self.all_keywords
    }

    pub const fn requires_all_fields(&self) -> bool {
        self.all_fields
    }
}

impl std::fmt::Display for SearchField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrivateKey => write!(f, "private-key"),
            Self::PublicKey => write!(f, "public-key"),
            Self::Sha256Fingerprint => write!(f, "sha256-fingerprint"),
            Self::Sha512Fingerprint => write!(f, "sha512-fingerprint"),
        }
    }
}
