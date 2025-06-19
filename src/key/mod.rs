use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use smallstr::SmallString;
use smallvec::SmallVec;

use crate::{cli::SearchField, key};

pub mod ed25519;

// pub struct SSHKey<K: Key> {
//     key: K,
// }

// impl<K: Key> SSHKey<K> {
//     pub fn new(key: K) -> Self {
//         Self { key }
//     }

//     pub fn signing_key(&self) -> &K::SigningKey {
//         &self.key.signing_key()
//     }

//     pub fn verifying_key(&self) -> &K::VerifyingKey {
//         &self.key.verifying_key()
//     }
// }

pub trait Key {
    type SigningKey;
    type VerifyingKey;

    const SSH_KEY_ALGORITHM_NAME: &'static str;

    const PUBLIC_KEY_SIZE: usize;
    const PRIVATE_KEY_SIZE: usize;

    fn signing_key(&self) -> &Self::SigningKey;
    fn verifying_key(&self) -> &Self::VerifyingKey;
}

pub trait SSHWireFormatter<K: Key> {
    const PUBLIC_KEY_WIRE_SIZE: usize;

    fn generate_public_key_wire(
        verifying_key: &K::VerifyingKey,
    ) -> SmallVec<[u8; Self::PUBLIC_KEY_WIRE_SIZE]>;

    fn get_sha256_fingerprint(verifying_key: &K::VerifyingKey) -> SmallString<[u8; 43]> {
        let mut fingerprint = SmallString::new_const();

        let raw_fingerprint = Self::get_raw_sha256_fingerprint(verifying_key);
        let mut fingerprint_buffer = [0u8; (32usize.div_ceil(3) * 4) - 1];
        STANDARD_NO_PAD
            .encode_slice(raw_fingerprint, &mut fingerprint_buffer)
            .unwrap();

        fingerprint.push_str(unsafe { str::from_utf8_unchecked(&fingerprint_buffer) });

        fingerprint
    }

    fn get_sha512_fingerprint(verifying_key: &K::VerifyingKey) -> SmallString<[u8; 87]> {
        let mut fingerprint = SmallString::new_const();

        let raw_fingerprint = Self::get_raw_sha512_fingerprint(verifying_key);
        let mut fingerprint_buffer = [0u8; (64usize.div_ceil(3) * 4) - 1];
        STANDARD_NO_PAD
            .encode_slice(raw_fingerprint, &mut fingerprint_buffer)
            .unwrap();

        fingerprint.push_str(unsafe { str::from_utf8_unchecked(&fingerprint_buffer) });

        fingerprint
    }

    // TODO: Add more digests?
    fn get_raw_sha256_fingerprint(verifying_key: &K::VerifyingKey) -> [u8; 32];
    fn get_raw_sha512_fingerprint(verifying_key: &K::VerifyingKey) -> [u8; 64];
}

pub trait OpenSSHFormatter<K: Key> {
    const OPENSSH_PRIVATE_KEY_MAGIC: &'static str = "openssh-key-v1\0";

    const OPENSSH_CIPHER_NAME: &'static str = "none";
    const OPENSSH_KDF_NAME: &'static str = "none";

    const OPENSSH_KDF_OPTIONS: &'static str = "";
    const OPENSSH_NUMBER_OF_KEYS: u32 = 1;

    const OPENSSH_COMMENT: &'static str = "";

    const OPENSSH_PEM_HEADER: &'static str = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
    const OPENSSH_PEM_FOOTER: &'static str = "-----END OPENSSH PRIVATE KEY-----\n";

    const OPENSSH_PUBLIC_KEY_SIZE: usize;
    const OPENSSH_PRIVATE_KEY_SIZE: usize;

    fn format_public_key(
        verifying_key: &K::VerifyingKey,
    ) -> SmallString<[u8; Self::OPENSSH_PUBLIC_KEY_SIZE]>;

    fn format_private_key(
        signing_key: &K::SigningKey,
        verifying_key: &K::VerifyingKey,
    ) -> SmallString<[u8; Self::OPENSSH_PRIVATE_KEY_SIZE]>;

    fn write_private_key_header_section<W: std::io::Write>(writer: &mut W) -> std::io::Result<()>;
    fn write_private_key_public_key_section<W: std::io::Write>(
        writer: &mut W,
        verifying_key: &K::VerifyingKey,
    ) -> std::io::Result<()>;
    fn write_private_key_private_key_section<W: std::io::Write>(
        writer: &mut W,
        signing_key: &K::SigningKey,
        verifying_key: &K::VerifyingKey,
    ) -> std::io::Result<()>;
}

pub struct SearchEngine {
    keywords: SmallVec<[SmallString<[u8; 6]>; 8]>,
    search_fields: SmallVec<[SearchField; 4]>,
    all_keywords: bool,
    all_fields: bool,
}

impl SearchEngine {
    pub const fn new(
        keywords: SmallVec<[SmallString<[u8; 6]>; 8]>,
        search_fields: SmallVec<[SearchField; 4]>,
        all_keywords: bool,
        all_fields: bool,
    ) -> Self {
        Self {
            keywords,
            search_fields,
            all_keywords,
            all_fields,
        }
    }

    pub fn search_matches(&self, key: &key::ed25519::Ed25519Key) -> bool {
        let mut sorted_fields = self.search_fields.iter().collect::<SmallVec<[_; 4]>>();
        sorted_fields.sort_unstable_by_key(|field| Self::field_priority(field));

        let mut field_match_count = 0;
        for field in &sorted_fields {
            let field_matches = self.search_field(field, key);

            if field_matches {
                field_match_count += 1;
                if !self.all_fields {
                    return true;
                }
            } else if self.all_fields {
                return false;
            }
        }

        if self.all_fields {
            field_match_count == sorted_fields.len()
        } else {
            field_match_count > 0
        }
    }

    fn search_field(&self, field: &SearchField, key: &key::ed25519::Ed25519Key) -> bool {
        match field {
            SearchField::PrivateKey => ByteSearch::large_keyword_search(
                key::ed25519::Ed25519Key::format_private_key(
                    key.signing_key(),
                    key.verifying_key(),
                )
                .as_bytes(),
                &self.keywords,
                self.all_keywords,
            ),
            SearchField::PublicKey => ByteSearch::fast_keyword_search(
                key::ed25519::Ed25519Key::format_public_key(key.verifying_key()).as_bytes(),
                &self.keywords,
                self.all_keywords,
            ),
            SearchField::Sha256Fingerprint => ByteSearch::fast_keyword_search(
                key::ed25519::Ed25519Key::get_sha256_fingerprint(key.verifying_key()).as_bytes(),
                &self.keywords,
                self.all_keywords,
            ),
            SearchField::Sha512Fingerprint => ByteSearch::fast_keyword_search(
                key::ed25519::Ed25519Key::get_sha512_fingerprint(key.verifying_key()).as_bytes(),
                &self.keywords,
                self.all_keywords,
            ),
        }
    }

    const fn field_priority(field: &SearchField) -> usize {
        match field {
            SearchField::Sha256Fingerprint => 0,
            SearchField::PublicKey => 1,
            SearchField::Sha512Fingerprint => 2,
            SearchField::PrivateKey => 3,
        }
    }
}

pub struct ByteSearch;
impl ByteSearch {
    pub fn fast_keyword_search(
        bytes: &[u8],
        keywords: &[SmallString<[u8; 6]>],
        all_keywords: bool,
    ) -> bool {
        if keywords.is_empty() {
            return true;
        }

        if all_keywords {
            keywords
                .iter()
                .all(|keyword| Self::contains_bytes(bytes, keyword.as_bytes()))
        } else {
            keywords
                .iter()
                .any(|keyword| Self::contains_bytes(bytes, keyword.as_bytes()))
        }
    }

    pub fn large_keyword_search(
        bytes: &[u8],
        keywords: &[SmallString<[u8; 6]>],
        all_keywords: bool,
    ) -> bool {
        let mut keywords = keywords.iter().collect::<SmallVec<[_; 8]>>();
        keywords.sort_unstable_by_key(|k| k.len());

        if all_keywords {
            keywords
                .iter()
                .all(|keyword| Self::contains_bytes(bytes, keyword.as_bytes()))
        } else {
            keywords
                .iter()
                .any(|keyword| Self::contains_bytes(bytes, keyword.as_bytes()))
        }
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }

        if needle.len() > haystack.len() {
            return false;
        }

        if needle.len() == 1 {
            return memchr::memchr(needle[0], haystack).is_some();
        }

        memchr::memmem::find(haystack, needle).is_some()
    }
}
