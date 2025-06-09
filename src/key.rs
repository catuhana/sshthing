// Parts of this code is written by Claude Sonnet 4.

use std::sync::OnceLock;

use base64::Engine;
use ed25519_dalek::{SecretKey, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};

pub struct Ed25519Key {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub key_info: OnceLock<KeyInfo>,
}

#[derive(Debug)]
pub struct KeyInfo {
    pub private_key_openssh: String,
    pub public_key_openssh: String,
    pub sha256_fingerprint: String,
    pub sha512_fingerprint: String,
}

impl Ed25519Key {
    // SSH wire format constants
    const SSH_KEY_TYPE: &[u8] = b"ssh-ed25519";
    const SSH_KEY_TYPE_LENGTH: u32 = Self::SSH_KEY_TYPE.len() as u32;
    const SSH_KEY_TYPE_LENGTH_BYTES: [u8; 4] = Self::SSH_KEY_TYPE_LENGTH.to_be_bytes();

    // Ed25519 key size constants
    const ED25519_PUBLIC_KEY_SIZE: u32 = 32;
    const ED25519_PRIVATE_KEY_SIZE: u32 = 32;
    const ED25519_SIGNATURE_SIZE: u32 = 64;
    const ED25519_PUBLIC_KEY_LENGTH_BYTES: [u8; 4] = Self::ED25519_PUBLIC_KEY_SIZE.to_be_bytes();

    // OpenSSH format constants
    const OPENSSH_AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";
    const OPENSSH_CIPHER_NONE: &[u8] = b"none";
    const OPENSSH_KDF_NONE: &[u8] = b"none";
    const OPENSSH_DEFAULT_COMMENT: &[u8] = b"";
    const OPENSSH_CHECK_INT: u32 = 0x1234_5678;
    const OPENSSH_CHECK_INT_BYTES: [u8; 4] = Self::OPENSSH_CHECK_INT.to_be_bytes();

    // Pre-computed length constants
    const OPENSSH_CIPHER_NONE_LEN: u32 = Self::OPENSSH_CIPHER_NONE.len() as u32;
    const OPENSSH_KDF_NONE_LEN: u32 = Self::OPENSSH_KDF_NONE.len() as u32;
    const OPENSSH_DEFAULT_COMMENT_LEN: u32 = Self::OPENSSH_DEFAULT_COMMENT.len() as u32;

    const OPENSSH_CIPHER_NONE_LEN_BYTES: [u8; 4] = Self::OPENSSH_CIPHER_NONE_LEN.to_be_bytes();
    const OPENSSH_KDF_NONE_LEN_BYTES: [u8; 4] = Self::OPENSSH_KDF_NONE_LEN.to_be_bytes();
    const OPENSSH_DEFAULT_COMMENT_LEN_BYTES: [u8; 4] =
        Self::OPENSSH_DEFAULT_COMMENT_LEN.to_be_bytes();

    // Calculated sizes for buffer allocation
    const SSH_PUBLIC_KEY_WIRE_SIZE: usize =
        4 + Self::SSH_KEY_TYPE.len() + 4 + Self::ED25519_PUBLIC_KEY_SIZE as usize;

    // Private key section size (before padding)
    const OPENSSH_PRIVATE_SECTION_UNPADDED_SIZE: usize = 4 + 4 + // two check integers
        4 + Self::SSH_KEY_TYPE.len() + // key type
        4 + Self::ED25519_PUBLIC_KEY_SIZE as usize + // public key
        4 + (Self::ED25519_PRIVATE_KEY_SIZE + Self::ED25519_PUBLIC_KEY_SIZE) as usize + // private key (32 bytes private + 32 bytes public)
        4 + Self::OPENSSH_DEFAULT_COMMENT.len(); // comment

    // Padding calculation (must be multiple of 8)
    const OPENSSH_PADDING_LENGTH: usize =
        (8 - (Self::OPENSSH_PRIVATE_SECTION_UNPADDED_SIZE % 8)) % 8;
    const OPENSSH_PRIVATE_SECTION_PADDED_SIZE: usize =
        Self::OPENSSH_PRIVATE_SECTION_UNPADDED_SIZE + Self::OPENSSH_PADDING_LENGTH;

    // Total private key buffer size
    const OPENSSH_PRIVATE_KEY_BUFFER_SIZE: usize = Self::OPENSSH_AUTH_MAGIC.len() +
        4 + Self::OPENSSH_CIPHER_NONE.len() + // cipher
        4 + Self::OPENSSH_KDF_NONE.len() + // kdf
        4 + // kdf options length (0)
        4 + // number of keys (1)
        4 + Self::SSH_PUBLIC_KEY_WIRE_SIZE + // public key section
        4 + Self::OPENSSH_PRIVATE_SECTION_PADDED_SIZE; // private section

    // Pre-computed constants for common byte sequences
    const ZERO_U32_BYTES: [u8; 4] = 0u32.to_be_bytes();
    const ONE_U32_BYTES: [u8; 4] = 1u32.to_be_bytes();
    const SSH_PUBLIC_KEY_WIRE_SIZE_BYTES: [u8; 4] =
        (Self::SSH_PUBLIC_KEY_WIRE_SIZE as u32).to_be_bytes();
    const OPENSSH_PRIVATE_SECTION_PADDED_SIZE_BYTES: [u8; 4] =
        (Self::OPENSSH_PRIVATE_SECTION_PADDED_SIZE as u32).to_be_bytes();

    // Pre-computed padding sequence
    const PADDING_SEQUENCE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    #[inline]
    pub fn new_from_secret_key(secret_key: SecretKey) -> Self {
        let signing_key = SigningKey::from(secret_key);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
            key_info: OnceLock::default(),
        }
    }

    pub fn get_key_info(&self) -> &KeyInfo {
        self.key_info.get_or_init(|| {
            let mut private_key_buffer =
                Vec::with_capacity(Self::estimated_private_key_output_size());
            let mut public_key_buffer =
                Vec::with_capacity(Self::estimated_public_key_output_size());

            unsafe {
                self.write_openssh_private(&mut private_key_buffer)
                    .unwrap_unchecked();
                self.write_openssh_public(&mut public_key_buffer)
                    .unwrap_unchecked();
            }

            let private_key_openssh = unsafe { String::from_utf8_unchecked(private_key_buffer) };
            let public_key_openssh = unsafe { String::from_utf8_unchecked(public_key_buffer) };

            let (sha256_fingerprint, sha512_fingerprint) = self.generate_fingerprints();

            KeyInfo {
                private_key_openssh,
                public_key_openssh,
                sha256_fingerprint,
                sha512_fingerprint,
            }
        })
    }

    pub fn generate_fingerprints(&self) -> (String, String) {
        let mut public_key_wire = Vec::with_capacity(Self::SSH_PUBLIC_KEY_WIRE_SIZE);
        public_key_wire.extend_from_slice(&Self::SSH_KEY_TYPE_LENGTH_BYTES);
        public_key_wire.extend_from_slice(Self::SSH_KEY_TYPE);
        public_key_wire.extend_from_slice(&Self::ED25519_PUBLIC_KEY_LENGTH_BYTES);
        public_key_wire.extend_from_slice(self.verifying_key.as_bytes());

        let mut sha256_hasher = Sha256::new();
        let mut sha512_hasher = Sha512::new();

        sha256_hasher.update(&public_key_wire);
        sha512_hasher.update(&public_key_wire);

        let sha256_hash = sha256_hasher.finalize();
        let sha512_hash = sha512_hasher.finalize();

        let mut sha256_output = String::with_capacity(44);
        let mut sha512_output = String::with_capacity(88);

        base64::engine::general_purpose::STANDARD.encode_string(sha256_hash, &mut sha256_output);
        base64::engine::general_purpose::STANDARD.encode_string(sha512_hash, &mut sha512_output);

        (sha256_output, sha512_output)
    }

    pub fn matches_search(
        &self,
        keywords: &[String],
        fields: &[crate::cli::SearchField],
        all_keywords: bool,
        all_fields: bool,
    ) -> bool {
        let key_info = self.get_key_info();

        let mut sorted_fields: Vec<_> = fields.iter().collect();
        sorted_fields.sort_by_key(|field| match field {
            crate::cli::SearchField::Sha256Fingerprint => 0,
            crate::cli::SearchField::Sha512Fingerprint => 1,
            crate::cli::SearchField::PublicKey => 2,
            crate::cli::SearchField::PrivateKey => 3,
        });

        let mut field_match_count = 0;

        for &field in &sorted_fields {
            let field_matches = match field {
                crate::cli::SearchField::Sha256Fingerprint => {
                    Self::fast_keyword_search(&key_info.sha256_fingerprint, keywords, all_keywords)
                }
                crate::cli::SearchField::Sha512Fingerprint => {
                    Self::fast_keyword_search(&key_info.sha512_fingerprint, keywords, all_keywords)
                }
                crate::cli::SearchField::PublicKey => {
                    Self::fast_keyword_search(&key_info.public_key_openssh, keywords, all_keywords)
                }
                crate::cli::SearchField::PrivateKey => Self::optimized_large_string_search(
                    &key_info.private_key_openssh,
                    keywords,
                    all_keywords,
                ),
            };

            if field_matches {
                field_match_count += 1;
                if !all_fields {
                    return true;
                }
            } else if all_fields {
                return false;
            }
        }

        if all_fields {
            field_match_count == sorted_fields.len()
        } else {
            field_match_count > 0
        }
    }

    #[inline]
    fn fast_keyword_search(text: &str, keywords: &[String], all_keywords: bool) -> bool {
        let text_bytes = text.as_bytes();

        if all_keywords {
            keywords
                .iter()
                .all(|keyword| Self::contains_bytes(text_bytes, keyword.as_bytes()))
        } else {
            keywords
                .iter()
                .any(|keyword| Self::contains_bytes(text_bytes, keyword.as_bytes()))
        }
    }

    #[inline]
    fn optimized_large_string_search(text: &str, keywords: &[String], all_keywords: bool) -> bool {
        let text_bytes = text.as_bytes();

        let mut keyword_refs: Vec<_> = keywords.iter().collect();
        keyword_refs.sort_by_key(|k| k.len());

        if all_keywords {
            keyword_refs
                .iter()
                .all(|keyword| Self::contains_bytes(text_bytes, keyword.as_bytes()))
        } else {
            keyword_refs
                .iter()
                .any(|keyword| Self::contains_bytes(text_bytes, keyword.as_bytes()))
        }
    }

    #[inline]
    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        if needle.len() > haystack.len() {
            return false;
        }

        if needle.len() == 1 {
            let target = needle[0];
            return haystack.contains(&target);
        }

        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[inline]
    pub fn write_openssh_public<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let mut buffer = Vec::with_capacity(Self::SSH_PUBLIC_KEY_WIRE_SIZE);

        // Write the length of the key type string (4 bytes, big-endian)
        buffer.extend_from_slice(&Self::SSH_KEY_TYPE_LENGTH_BYTES);
        // Write the key type string "ssh-ed25519"
        buffer.extend_from_slice(Self::SSH_KEY_TYPE);
        // Write the length of the public key (32 bytes, big-endian)
        buffer.extend_from_slice(&Self::ED25519_PUBLIC_KEY_LENGTH_BYTES);
        // Write the actual 32-byte Ed25519 public key
        buffer.extend_from_slice(self.verifying_key.as_bytes());

        writer.write_all(b"ssh-ed25519 ")?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&buffer);
        writer.write_all(encoded.as_bytes())?;

        Ok(())
    }

    #[inline]
    pub fn write_openssh_private<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let mut buffer = Vec::with_capacity(Self::OPENSSH_PRIVATE_KEY_BUFFER_SIZE);

        // Write OpenSSH private key format magic header
        buffer.extend_from_slice(Self::OPENSSH_AUTH_MAGIC);

        // Write cipher name length and "none" (no encryption)
        buffer.extend_from_slice(&Self::OPENSSH_CIPHER_NONE_LEN_BYTES);
        buffer.extend_from_slice(Self::OPENSSH_CIPHER_NONE);

        // Write KDF name length and "none" (no key derivation function)
        buffer.extend_from_slice(&Self::OPENSSH_KDF_NONE_LEN_BYTES);
        buffer.extend_from_slice(Self::OPENSSH_KDF_NONE);

        // Write KDF options length (0 - no KDF options)
        buffer.extend_from_slice(&Self::ZERO_U32_BYTES);

        // Write number of keys (1 - single key file)
        buffer.extend_from_slice(&Self::ONE_U32_BYTES);

        // === PUBLIC KEY SECTION ===
        // Write public key section length
        buffer.extend_from_slice(&Self::SSH_PUBLIC_KEY_WIRE_SIZE_BYTES);
        // Write key type length and "ssh-ed25519"
        buffer.extend_from_slice(&Self::SSH_KEY_TYPE_LENGTH_BYTES);
        buffer.extend_from_slice(Self::SSH_KEY_TYPE);
        // Write public key length (32 bytes) and the actual public key
        buffer.extend_from_slice(&Self::ED25519_PUBLIC_KEY_LENGTH_BYTES);
        buffer.extend_from_slice(self.verifying_key.as_bytes());

        // === PRIVATE KEY SECTION ===
        // Write private section length (including padding)
        buffer.extend_from_slice(&Self::OPENSSH_PRIVATE_SECTION_PADDED_SIZE_BYTES);

        // Write check integers (used to verify successful decryption - same value twice)
        buffer.extend_from_slice(&Self::OPENSSH_CHECK_INT_BYTES);
        buffer.extend_from_slice(&Self::OPENSSH_CHECK_INT_BYTES);

        // Write key type length and "ssh-ed25519" again
        buffer.extend_from_slice(&Self::SSH_KEY_TYPE_LENGTH_BYTES);
        buffer.extend_from_slice(Self::SSH_KEY_TYPE);

        // Write public key length and public key (duplicated from above)
        buffer.extend_from_slice(&Self::ED25519_PUBLIC_KEY_LENGTH_BYTES);
        buffer.extend_from_slice(self.verifying_key.as_bytes());

        // Write private key length (64 bytes: 32 private + 32 public concatenated)
        buffer.extend_from_slice(&Self::ED25519_SIGNATURE_SIZE.to_be_bytes());
        // Write 32-byte private key followed by 32-byte public key
        buffer.extend_from_slice(self.signing_key.as_bytes());
        buffer.extend_from_slice(self.verifying_key.as_bytes());

        // Write comment length and comment (empty by default)
        buffer.extend_from_slice(&Self::OPENSSH_DEFAULT_COMMENT_LEN_BYTES);
        buffer.extend_from_slice(Self::OPENSSH_DEFAULT_COMMENT);

        // Add padding bytes (1, 2, 3, ...) to align private section to 8-byte boundary
        buffer.extend_from_slice(&Self::PADDING_SEQUENCE[..Self::OPENSSH_PADDING_LENGTH]);

        writer.write_all(b"-----BEGIN OPENSSH PRIVATE KEY-----\n")?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&buffer);
        for chunk in encoded.as_bytes().chunks(70) {
            writer.write_all(chunk)?;
            writer.write_all(b"\n")?;
        }
        writer.write_all(b"-----END OPENSSH PRIVATE KEY-----\n")?;

        Ok(())
    }

    const fn estimated_public_key_output_size() -> usize {
        // "ssh-ed25519 " + base64 encoded size + some padding
        12 + (Self::SSH_PUBLIC_KEY_WIRE_SIZE * 4).div_ceil(3) + 4
    }

    const fn estimated_private_key_output_size() -> usize {
        // Headers + base64 encoded size + newlines + padding
        64 + (Self::OPENSSH_PRIVATE_KEY_BUFFER_SIZE * 4).div_ceil(3) + 100
    }
}
