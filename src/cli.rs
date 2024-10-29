// TODO: Re-consider some flags.
#[derive(clap::Parser, Debug)]
pub struct Cli {
    /// The keywords to search for in SSH fields
    #[arg(long, short = 'K', required = true)]
    pub keywords: Vec<String>,

    /// Generated SSH fields to search in
    #[arg(long, short = 'S')]
    pub search_in: SearchIn,

    #[arg(long)]
    pub match_mode: MatchMode,

    /// The number of threads to use
    #[arg(long, short, default_value_t = num_cpus::get())]
    pub threads: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchIn {
    Specific(Vec<SearchField>),
    Keys,
    Fingerprints,
    All,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchField {
    PrivateKey,
    PublicKey,
    Fingerprint(HashType),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashType {
    Sha256,
    Sha512,
}

#[derive(Clone, Debug)]
pub enum MatchMode {
    All,
    Any,
}

impl std::str::FromStr for SearchIn {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "keys" => Ok(Self::Keys),
            "fingerprints" => Ok(Self::Fingerprints),
            "all" => Ok(Self::All),
            _ => {
                let fields: Result<Vec<SearchField>, _> = s
                    .split(',')
                    .map(str::trim)
                    .map(SearchField::from_str)
                    .collect();

                match fields {
                    Ok(fields) if !fields.is_empty() => Ok(Self::Specific(fields)),
                    _ => Err(format!("Invalid search in: {s}")),
                }
            }
        }
    }
}

impl std::str::FromStr for MatchMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "all" => Ok(Self::All),
            "any" => Ok(Self::Any),
            _ => Err(format!("Invalid match mode: {s}")),
        }
    }
}

impl std::str::FromStr for SearchField {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "private" | "private-key" => Ok(Self::PrivateKey),
            "public" | "public-key" => Ok(Self::PublicKey),
            "sha256" | "sha256-fingerprint" => Ok(Self::Fingerprint(HashType::Sha256)),
            "sha512" | "sha512-fingerprint" => Ok(Self::Fingerprint(HashType::Sha512)),
            _ => Err(format!("Invalid search field: {s}")),
        }
    }
}
