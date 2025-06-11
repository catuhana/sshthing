use base64::Engine;
use ed25519_dalek::{SecretKey, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};
use smallvec::SmallVec;

use crate::errors::KeyError;

pub struct Ed25519Key {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
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

    pub fn new_from_secret_key(secret_key: SecretKey) -> Self {
        let signing_key = SigningKey::from(secret_key);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    fn generate_public_key_wire(&self) -> SmallVec<[u8; Self::SSH_PUBLIC_KEY_WIRE_SIZE]> {
        let mut public_key_wire: SmallVec<[u8; Self::SSH_PUBLIC_KEY_WIRE_SIZE]> =
            SmallVec::new_const();

        public_key_wire.extend_from_slice(&Self::SSH_KEY_TYPE_LENGTH_BYTES);
        public_key_wire.extend_from_slice(Self::SSH_KEY_TYPE);
        public_key_wire.extend_from_slice(&Self::ED25519_PUBLIC_KEY_LENGTH_BYTES);
        public_key_wire.extend_from_slice(self.verifying_key.as_bytes());

        public_key_wire
    }

    pub fn generate_sha256_fingerprint(&self) -> String {
        let public_key_wire = self.generate_public_key_wire();

        let mut hasher = Sha256::new();
        hasher.update(&public_key_wire);
        let hash = hasher.finalize();

        // Omit the trailing padding
        let mut output = String::with_capacity(43);
        base64::engine::general_purpose::STANDARD.encode_string(hash, &mut output);

        output
    }

    pub fn generate_sha512_fingerprint(&self) -> String {
        let public_key_wire = self.generate_public_key_wire();

        let mut hasher = Sha512::new();
        hasher.update(&public_key_wire);
        let hash = hasher.finalize();

        // Omit the trailing padding
        let mut output = String::with_capacity(86);
        base64::engine::general_purpose::STANDARD.encode_string(hash, &mut output);

        output
    }

    pub fn generate_public_key_openssh(&self) -> String {
        let buffer = self.generate_public_key_wire();

        let mut result = String::with_capacity(Self::estimated_public_key_output_size());
        result.push_str("ssh-ed25519 ");
        base64::engine::general_purpose::STANDARD.encode_string(&buffer, &mut result);

        result
    }

    pub fn generate_private_key_openssh(&self) -> String {
        let mut buffer: SmallVec<[u8; Self::OPENSSH_PRIVATE_KEY_BUFFER_SIZE]> =
            SmallVec::new_const();

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

        let mut result = String::with_capacity(Self::estimated_private_key_output_size());
        result.push_str("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(&buffer);
        for chunk in encoded.as_bytes().chunks(70) {
            unsafe {
                result.push_str(std::str::from_utf8_unchecked(chunk));
            }
            result.push('\n');
        }
        result.push_str("-----END OPENSSH PRIVATE KEY-----\n");
        result
    }

    pub fn matches_search(
        &self,
        keywords: &[String],
        fields: &[crate::cli::SearchField],
        all_keywords: bool,
        all_fields: bool,
    ) -> bool {
        let mut sorted_fields: SmallVec<[&crate::cli::SearchField; 4]> = fields.iter().collect();
        sorted_fields.sort_by_key(|field| match field {
            crate::cli::SearchField::Sha256Fingerprint => 0,
            crate::cli::SearchField::Sha512Fingerprint => 1,
            crate::cli::SearchField::PublicKey => 2,
            crate::cli::SearchField::PrivateKey => 3,
        });

        let mut field_match_count = 0;

        for &field in &sorted_fields {
            let field_matches = match field {
                crate::cli::SearchField::Sha256Fingerprint => Self::fast_keyword_search(
                    &self.generate_sha256_fingerprint(),
                    keywords,
                    all_keywords,
                ),
                crate::cli::SearchField::Sha512Fingerprint => Self::fast_keyword_search(
                    &self.generate_sha512_fingerprint(),
                    keywords,
                    all_keywords,
                ),
                crate::cli::SearchField::PublicKey => Self::fast_keyword_search(
                    &self.generate_public_key_openssh(),
                    keywords,
                    all_keywords,
                ),
                crate::cli::SearchField::PrivateKey => Self::optimized_large_string_search(
                    &self.generate_private_key_openssh(),
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

    fn optimized_large_string_search(text: &str, keywords: &[String], all_keywords: bool) -> bool {
        let text_bytes = text.as_bytes();

        // Let's assume max of 8 keywords
        let mut keyword_refs: SmallVec<[&String; 8]> = keywords.iter().collect();
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

    pub fn write_openssh_public<W: std::io::Write>(&self, writer: &mut W) -> Result<(), KeyError> {
        Ok(writer.write_all(self.generate_public_key_openssh().as_bytes())?)
    }

    pub fn write_openssh_private<W: std::io::Write>(&self, writer: &mut W) -> Result<(), KeyError> {
        Ok(writer.write_all(self.generate_private_key_openssh().as_bytes())?)
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
