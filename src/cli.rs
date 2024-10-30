#[derive(clap::Parser, Debug)]
pub struct Cli {
    /// The keywords to search for in SSH fields
    #[arg(long, short = 'K', value_delimiter = ',', required = true)]
    pub keywords: Vec<String>,

    /// Generated SSH fields to search in
    #[arg(long, short = 'S', default_value_t = SearchIn::default())]
    pub search_in: SearchIn,

    /// Match mode for keywords
    #[arg(long, default_value_t = KeywordsMatchMode::default())]
    pub keywords_match_mode: KeywordsMatchMode,

    /// Match mode for search fields
    #[arg(long, default_value_t = SearchMatchMode::default())]
    pub search_match_mode: SearchMatchMode,

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

#[derive(Clone, Debug, Default)]
pub enum KeywordsMatchMode {
    Specific(Vec<String>),
    #[default]
    All,
    Any,
}

#[derive(Clone, Debug, Default)]
pub enum SearchMatchMode {
    Specific(Vec<SearchField>),
    #[default]
    All,
    Any,
}

impl Default for SearchIn {
    fn default() -> Self {
        Self::Specific(vec![SearchField::Fingerprint(HashType::Sha256)])
    }
}

impl std::fmt::Display for SearchIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keys => write!(f, "keys"),
            Self::Fingerprints => write!(f, "fingerprints"),
            Self::All => write!(f, "all"),
            Self::Specific(fields) => write!(
                f,
                "{}",
                fields
                    .iter()
                    .map(SearchField::to_string)
                    .collect::<Vec<String>>()
                    .join(",")
            ),
        }
    }
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

impl std::fmt::Display for SearchField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrivateKey => write!(f, "private-key"),
            Self::PublicKey => write!(f, "public-key"),
            Self::Fingerprint(HashType::Sha256) => write!(f, "sha256-fingerprint"),
            Self::Fingerprint(HashType::Sha512) => write!(f, "sha512-fingerprint"),
        }
    }
}

impl std::str::FromStr for KeywordsMatchMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "all" => Ok(Self::All),
            "any" => Ok(Self::Any),
            _ => {
                let fields = s
                    .split(',')
                    .map(str::trim)
                    .map(String::from)
                    .collect::<Vec<String>>();

                if fields.is_empty() {
                    return Err(format!("Invalid keywords match mode: {s}"));
                }

                Ok(Self::Specific(fields))
            }
        }
    }
}

impl std::fmt::Display for KeywordsMatchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Specific(fields) => write!(f, "{}", fields.join(",")),
            Self::All => write!(f, "all"),
            Self::Any => write!(f, "any"),
        }
    }
}

impl std::str::FromStr for SearchMatchMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "all" => Ok(Self::All),
            "any" => Ok(Self::Any),
            _ => {
                let fields: Result<Vec<SearchField>, _> = s
                    .split(',')
                    .map(str::trim)
                    .map(SearchField::from_str)
                    .collect();

                match fields {
                    Ok(fields) if !fields.is_empty() => Ok(Self::Specific(fields)),
                    _ => Err(format!("Invalid search match mode: {s}")),
                }
            }
        }
    }
}

impl std::fmt::Display for SearchMatchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::All => write!(f, "all"),
            Self::Any => write!(f, "any"),
            Self::Specific(fields) => write!(
                f,
                "{}",
                fields
                    .iter()
                    .map(SearchField::to_string)
                    .collect::<Vec<String>>()
                    .join(",")
            ),
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
