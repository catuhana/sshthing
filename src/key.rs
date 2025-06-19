use aho_corasick::AhoCorasick;
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};
use smallstr::SmallString;
use smallvec::SmallVec;

use crate::cli::SearchField;

pub struct Ed25519 {
    pub public_key_fingerprint_sha256: SmallString<[u8; 43]>,
    pub public_key_fingerprint_sha512: SmallString<[u8; 87]>,
    pub public_key_openssh: SmallString<[u8; Ed25519::OPENSSH_PUBLIC_KEY_SIZE]>,
    pub private_key_openssh: SmallString<[u8; Ed25519::OPENSSH_PRIVATE_KEY_SIZE]>,
}

impl Ed25519 {
    pub const SSH_KEY_ALGORITHM_NAME: &'static str = "ssh-ed25519";
    pub const PUBLIC_KEY_SIZE: usize = 32;
    pub const PRIVATE_KEY_SIZE: usize = 32;

    pub const PUBLIC_KEY_WIRE_SIZE: usize =
        4 + Self::SSH_KEY_ALGORITHM_NAME.len() + 4 + Self::PUBLIC_KEY_SIZE;

    pub const OPENSSH_PRIVATE_KEY_MAGIC: &'static str = "openssh-key-v1\0";
    pub const OPENSSH_CIPHER_NAME: &'static str = "none";
    pub const OPENSSH_KDF_NAME: &'static str = "none";
    pub const OPENSSH_KDF_OPTIONS: &'static str = "";
    pub const OPENSSH_NUMBER_OF_KEYS: u32 = 1;
    pub const OPENSSH_COMMENT: &'static str = "";
    pub const OPENSSH_PEM_HEADER: &'static str = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
    pub const OPENSSH_PEM_FOOTER: &'static str = "-----END OPENSSH PRIVATE KEY-----\n";

    const OPENSSH_PRIVATE_SECTION_CONTENT_SIZE: usize = (4 + 4) // 4 + 4 = 8 bytes: check integers
        + 4 + Self::SSH_KEY_ALGORITHM_NAME.len()                // 4 + 11 bytes: "ssh-ed25519"
        + 4 + Self::PUBLIC_KEY_SIZE                             // 4 + 32 bytes: public key
        + 4 + (Self::PRIVATE_KEY_SIZE + Self::PUBLIC_KEY_SIZE)  // 4 + 32 + 32 bytes: private key + public key
        + 4; // 4 + 0 bytes: comment (empty)

    const OPENSSH_PUBLIC_KEY_SIZE: usize =
        Self::SSH_KEY_ALGORITHM_NAME.len() + 1 + (Self::PUBLIC_KEY_WIRE_SIZE.div_ceil(3) * 4);

    const OPENSSH_PRIVATE_KEY_SIZE: usize =
        Self::OPENSSH_PEM_HEADER.len() + Self::OPENSSH_PEM_FOOTER.len() + {
            let base64_size = Self::OPENSSH_PRIVATE_KEY_BINARY_SIZE.div_ceil(3) * 4;
            let line_breaks = base64_size / 70;
            base64_size + line_breaks
        };

    const OPENSSH_PRIVATE_KEY_BINARY_SIZE: usize = {
        let header = Self::OPENSSH_PRIVATE_KEY_MAGIC.len()          // 15 bytes: "openssh-key-v1\0"
                + 4 + Self::OPENSSH_CIPHER_NAME.len()               // 4 + 4 = 8 bytes: "none"
                + 4 + Self::OPENSSH_KDF_NAME.len()                  // 4 + 4 = 8 bytes: "none"
                + 4 + Self::OPENSSH_KDF_OPTIONS.len()               // 4 + 0 = 4 bytes: ""
                + Self::OPENSSH_NUMBER_OF_KEYS.to_be_bytes().len(); // 4 bytes: number of keys (1)

        let public_section = 4                // 4 bytes: public key section length
                + Self::PUBLIC_KEY_WIRE_SIZE; // wire format size

        let private_section = 4                                   // 4 bytes: private section length
                + Self::OPENSSH_PRIVATE_KEY_PRIVATE_SECTION_SIZE; // private section size

        header + public_section + private_section
    };

    const OPENSSH_PRIVATE_KEY_PRIVATE_SECTION_SIZE: usize =
        Self::OPENSSH_PRIVATE_SECTION_CONTENT_SIZE
            + (8 - (Self::OPENSSH_PRIVATE_SECTION_CONTENT_SIZE % 8)) % 8;

    pub fn new_from_secret_key(secret_key: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from(secret_key);
        let verifying_key = signing_key.verifying_key();

        let public_key_wire = Self::generate_public_key_wire(&verifying_key);

        let public_key_fingerprint_sha256 = Self::get_sha256_fingerprint(&public_key_wire);
        let public_key_fingerprint_sha512 = Self::get_sha512_fingerprint(&public_key_wire);

        let public_key_openssh = Self::format_public_key(&public_key_wire);
        let private_key_openssh =
            Self::format_private_key(&signing_key, &verifying_key, &public_key_wire);

        Self {
            public_key_fingerprint_sha256,
            public_key_fingerprint_sha512,
            public_key_openssh,
            private_key_openssh,
        }
    }

    pub fn generate_public_key_wire(
        verifying_key: &VerifyingKey,
    ) -> SmallVec<[u8; Self::PUBLIC_KEY_WIRE_SIZE]> {
        let mut wire = SmallVec::new_const();

        wire.extend_from_slice(&(Self::SSH_KEY_ALGORITHM_NAME.len() as u32).to_be_bytes());
        wire.extend_from_slice(Self::SSH_KEY_ALGORITHM_NAME.as_bytes());

        wire.extend_from_slice(&(Self::PUBLIC_KEY_SIZE as u32).to_be_bytes());
        wire.extend_from_slice(verifying_key.as_bytes());

        wire
    }

    pub fn get_sha256_fingerprint(
        public_key_wire: &SmallVec<[u8; Self::PUBLIC_KEY_WIRE_SIZE]>,
    ) -> SmallString<[u8; 43]> {
        let mut fingerprint = SmallString::new_const();

        let raw_fingerprint = Sha256::digest(public_key_wire);
        let mut fingerprint_buffer = [0u8; (32usize.div_ceil(3) * 4) - 1];
        STANDARD_NO_PAD
            .encode_slice(raw_fingerprint, &mut fingerprint_buffer)
            .unwrap();

        fingerprint.push_str(unsafe { str::from_utf8_unchecked(&fingerprint_buffer) });
        fingerprint
    }

    pub fn get_sha512_fingerprint(
        public_key_wire: &SmallVec<[u8; Self::PUBLIC_KEY_WIRE_SIZE]>,
    ) -> SmallString<[u8; 87]> {
        let mut fingerprint = SmallString::new_const();

        let raw_fingerprint = Sha512::digest(public_key_wire);
        let mut fingerprint_buffer = [0u8; (64usize.div_ceil(3) * 4) - 1];
        STANDARD_NO_PAD
            .encode_slice(raw_fingerprint, &mut fingerprint_buffer)
            .unwrap();

        fingerprint.push_str(unsafe { str::from_utf8_unchecked(&fingerprint_buffer) });
        fingerprint
    }

    pub fn format_public_key(
        public_key_wire: &SmallVec<[u8; Self::PUBLIC_KEY_WIRE_SIZE]>,
    ) -> SmallString<[u8; Self::OPENSSH_PUBLIC_KEY_SIZE]> {
        let mut public_key = SmallString::new_const();

        public_key.push_str(Self::SSH_KEY_ALGORITHM_NAME);
        public_key.push(' ');

        let key_wire_base64 = STANDARD_NO_PAD.encode(public_key_wire);
        public_key.push_str(&key_wire_base64);

        public_key
    }

    pub fn format_private_key(
        signing_key: &SigningKey,
        verifying_key: &VerifyingKey,
        public_key_wire: &SmallVec<[u8; Self::PUBLIC_KEY_WIRE_SIZE]>,
    ) -> SmallString<[u8; Self::OPENSSH_PRIVATE_KEY_SIZE]> {
        let mut private_key = SmallString::new_const();
        let mut private_key_buffer = SmallVec::<[u8; Self::OPENSSH_PRIVATE_KEY_BINARY_SIZE]>::new();

        private_key.push_str(Self::OPENSSH_PEM_HEADER);

        Self::write_private_key_header_section(&mut private_key_buffer)
            .expect("Failed to write OpenSSH private key header section");
        Self::write_private_key_public_key_section(public_key_wire, &mut private_key_buffer)
            .expect("Failed to write OpenSSH private key public key section");
        Self::write_private_key_private_key_section(
            signing_key,
            verifying_key,
            &mut private_key_buffer,
        )
        .expect("Failed to write OpenSSH private key private key section");

        let mut encoded_key = [0u8; Self::OPENSSH_PRIVATE_KEY_BINARY_SIZE.div_ceil(3) * 4];
        STANDARD_NO_PAD
            .encode_slice(&private_key_buffer, &mut encoded_key)
            .unwrap();
        for chunk in encoded_key.chunks(70) {
            private_key.push_str(unsafe { str::from_utf8_unchecked(chunk) });
            private_key.push('\n');
        }

        private_key.push_str(Self::OPENSSH_PEM_FOOTER);
        private_key
    }

    fn write_private_key_header_section<W: std::io::Write>(writer: &mut W) -> std::io::Result<()> {
        writer.write_all(Self::OPENSSH_PRIVATE_KEY_MAGIC.as_bytes())?;

        writer.write_all(&(Self::OPENSSH_CIPHER_NAME.len() as u32).to_be_bytes())?;
        writer.write_all(Self::OPENSSH_CIPHER_NAME.as_bytes())?;

        writer.write_all(&(Self::OPENSSH_KDF_NAME.len() as u32).to_be_bytes())?;
        writer.write_all(Self::OPENSSH_KDF_NAME.as_bytes())?;

        writer.write_all(&0u32.to_be_bytes())?;
        writer.write_all(&1u32.to_be_bytes())?;

        Ok(())
    }

    fn write_private_key_public_key_section<W: std::io::Write>(
        public_key_wire: &SmallVec<[u8; Self::PUBLIC_KEY_WIRE_SIZE]>,
        writer: &mut W,
    ) -> std::io::Result<()> {
        writer.write_all(&(public_key_wire.len() as u32).to_be_bytes())?;
        writer.write_all(public_key_wire)?;

        Ok(())
    }

    fn write_private_key_private_key_section<W: std::io::Write>(
        signing_key: &SigningKey,
        verifying_key: &VerifyingKey,
        writer: &mut W,
    ) -> std::io::Result<()> {
        writer.write_all(&(Self::OPENSSH_PRIVATE_KEY_PRIVATE_SECTION_SIZE as u32).to_be_bytes())?;

        let mut check_int_buffer = [0u8; 4];
        rand::fill(&mut check_int_buffer[..]);
        writer.write_all(&check_int_buffer)?;
        writer.write_all(&check_int_buffer)?;

        writer.write_all(&(Self::SSH_KEY_ALGORITHM_NAME.len() as u32).to_be_bytes())?;
        writer.write_all(Self::SSH_KEY_ALGORITHM_NAME.as_bytes())?;

        writer.write_all(&(Self::PUBLIC_KEY_SIZE as u32).to_be_bytes())?;
        writer.write_all(verifying_key.as_bytes())?;

        writer
            .write_all(&((Self::PUBLIC_KEY_SIZE + Self::PRIVATE_KEY_SIZE) as u32).to_be_bytes())?;
        writer.write_all(signing_key.as_bytes())?;
        writer.write_all(verifying_key.as_bytes())?;

        writer.write_all(&(Self::OPENSSH_COMMENT.len() as u32).to_be_bytes())?;
        writer.write_all(Self::OPENSSH_COMMENT.as_bytes())?;

        let padding_length = (8 - (Self::OPENSSH_PRIVATE_SECTION_CONTENT_SIZE % 8)) % 8;
        for i in 1..=padding_length {
            writer.write_all(&[i as u8])?;
        }

        Ok(())
    }
}

pub struct SearchEngine {
    keywords: SmallVec<[SmallString<[u8; 6]>; 8]>,
    sorted_search_fields: SmallVec<[SearchField; 4]>,
    all_keywords: bool,
    all_fields: bool,
}

impl SearchEngine {
    pub fn new(
        keywords: SmallVec<[SmallString<[u8; 6]>; 8]>,
        mut search_fields: SmallVec<[SearchField; 4]>,
        all_keywords: bool,
        all_fields: bool,
    ) -> Self {
        search_fields.sort_unstable_by_key(Self::field_priority);

        Self {
            keywords,
            sorted_search_fields: search_fields,
            all_keywords,
            all_fields,
        }
    }

    pub fn search_matches(&self, key: &Ed25519) -> bool {
        if self.keywords.is_empty() {
            return true;
        }

        if self.all_fields {
            self.sorted_search_fields
                .iter()
                .all(|field| self.search_field(field, key))
        } else {
            self.sorted_search_fields
                .iter()
                .any(|field| self.search_field(field, key))
        }
    }

    fn search_field(&self, field: &SearchField, key: &Ed25519) -> bool {
        match field {
            SearchField::Sha256Fingerprint => ByteSearch::fast_keyword_search(
                key.public_key_fingerprint_sha256.as_bytes(),
                &self.keywords,
                self.all_keywords,
            ),
            SearchField::PublicKey => ByteSearch::fast_keyword_search(
                key.public_key_openssh.as_bytes(),
                &self.keywords,
                self.all_keywords,
            ),
            SearchField::Sha512Fingerprint => ByteSearch::fast_keyword_search(
                key.public_key_fingerprint_sha512.as_bytes(),
                &self.keywords,
                self.all_keywords,
            ),
            SearchField::PrivateKey => ByteSearch::large_keyword_search(
                key.private_key_openssh.as_bytes(),
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

        if keywords.len() == 1 {
            return Self::contains_bytes(bytes, keywords[0].as_bytes());
        }

        let mut sorted_keywords: SmallVec<[&[u8]; 8]> =
            keywords.iter().map(|k| k.as_bytes()).collect();
        if all_keywords {
            sorted_keywords.sort_unstable_by_key(|k| k.len());

            sorted_keywords
                .iter()
                .all(|&keyword| Self::contains_bytes(bytes, keyword))
        } else {
            sorted_keywords.sort_unstable_by_key(|k| std::cmp::Reverse(k.len()));

            sorted_keywords
                .iter()
                .any(|&keyword| Self::contains_bytes(bytes, keyword))
        }
    }

    pub fn large_keyword_search(
        bytes: &[u8],
        keywords: &[SmallString<[u8; 6]>],
        all_keywords: bool,
    ) -> bool {
        if keywords.is_empty() {
            return true;
        }

        if keywords.len() == 1 {
            return Self::contains_bytes(bytes, keywords[0].as_bytes());
        }

        if keywords.len() > 3 && !all_keywords {
            return Self::aho_corasick_search(bytes, keywords);
        }

        let mut sorted_keywords: SmallVec<[&[u8]; 8]> =
            keywords.iter().map(|k| k.as_bytes()).collect();

        if all_keywords {
            sorted_keywords.sort_unstable_by_key(|k| k.len());
            sorted_keywords
                .iter()
                .all(|&keyword| Self::contains_bytes(bytes, keyword))
        } else {
            sorted_keywords.sort_unstable_by_key(|k| std::cmp::Reverse(k.len()));
            sorted_keywords
                .iter()
                .any(|&keyword| Self::contains_bytes(bytes, keyword))
        }
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        match needle.len() {
            0 => true,
            1 => memchr::memchr(needle[0], haystack).is_some(),
            _ if needle.len() > haystack.len() => false,
            _ => memchr::memmem::find(haystack, needle).is_some(),
        }
    }

    fn aho_corasick_search(bytes: &[u8], keywords: &[SmallString<[u8; 6]>]) -> bool {
        let patterns = keywords
            .iter()
            .map(|k| k.as_bytes())
            .collect::<SmallVec<[&[u8]; 8]>>();
        let ac = AhoCorasick::new(&patterns).unwrap();

        ac.find(bytes).is_some()
    }
}
