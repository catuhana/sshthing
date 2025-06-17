use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};
use smallstr::SmallString;
use smallvec::SmallVec;

use crate::key::{Key, OpenSSHFormatter, SSHWireFormatter};

pub struct Ed25519Key {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl Ed25519Key {
    const OPENSSH_PRIVATE_SECTION_CONTENT_SIZE: usize = (4 + 4) // 4 + 4 = 8 bytes: check integers
        + 4 + Self::SSH_KEY_ALGORITHM_NAME.len()                // 4 + 11 bytes: "ssh-ed25519"
        + 4 + Self::PUBLIC_KEY_SIZE                             // 4 + 32 bytes: public key
        + 4 + (Self::PRIVATE_KEY_SIZE + Self::PUBLIC_KEY_SIZE)  // 4 + 32 + 32 bytes: private key + public key
        + 4; // 4 + 0 bytes: comment (empty)

    const OPENSSH_PUBLIC_KEY_SIZE: usize =
        Self::SSH_KEY_ALGORITHM_NAME.len() + 1 + (Self::PUBLIC_KEY_WIRE_SIZE.div_ceil(3) * 4);

    const OPENSSH_PRIVATE_KEY_SIZE: usize = <Self as OpenSSHFormatter<Self>>::OPENSSH_PEM_HEADER
        .len()
        + <Self as OpenSSHFormatter<Self>>::OPENSSH_PEM_FOOTER.len()
        + {
            let base64_size = Self::OPENSSH_PRIVATE_KEY_BINARY_SIZE.div_ceil(3) * 4;
            let line_breaks = base64_size / 70;

            base64_size + line_breaks
        };

    const OPENSSH_PRIVATE_KEY_BINARY_SIZE: usize = {
        let header = <Self as OpenSSHFormatter<Self>>::OPENSSH_PRIVATE_KEY_MAGIC.len()                          // 15 bytes: "openssh-key-v1\0"
                + 4 + <Self as OpenSSHFormatter<Self>>::OPENSSH_CIPHER_NAME.len()                               // 4 + 4 = 8 bytes: "none"
                + 4 + <Self as OpenSSHFormatter<Self>>::OPENSSH_KDF_NAME.len()                                  // 4 + 4 = 8 bytes: "none"
                + 4 + <Self as OpenSSHFormatter<Self>>::OPENSSH_KDF_OPTIONS.len()                               // 4 + 0 = 4 bytes: ""
                + <Self as OpenSSHFormatter<Self>>::OPENSSH_NUMBER_OF_KEYS.to_be_bytes().len(); // 4 bytes: number of keys (1)

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

        Self {
            signing_key,
            verifying_key,
        }
    }
}

impl Key for Ed25519Key {
    type SigningKey = SigningKey;
    type VerifyingKey = VerifyingKey;

    const SSH_KEY_ALGORITHM_NAME: &'static str = "ssh-ed25519";

    const PUBLIC_KEY_SIZE: usize = 32;
    const PRIVATE_KEY_SIZE: usize = 32;

    fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

impl SSHWireFormatter<Self> for Ed25519Key {
    const PUBLIC_KEY_WIRE_SIZE: usize =
        4 + Self::SSH_KEY_ALGORITHM_NAME.len() + 4 + Self::PUBLIC_KEY_SIZE;

    fn generate_public_key_wire(
        verifying_key: &<Self as Key>::VerifyingKey,
    ) -> SmallVec<[u8; Self::PUBLIC_KEY_WIRE_SIZE]> {
        let mut wire = SmallVec::new_const();

        wire.extend_from_slice(&(Self::SSH_KEY_ALGORITHM_NAME.len() as u32).to_be_bytes());
        wire.extend_from_slice(Self::SSH_KEY_ALGORITHM_NAME.as_bytes());

        wire.extend_from_slice(&(Self::PUBLIC_KEY_SIZE as u32).to_be_bytes());
        wire.extend_from_slice(verifying_key.as_bytes());

        wire
    }

    fn get_raw_sha256_fingerprint(verifying_key: &<Self as Key>::VerifyingKey) -> [u8; 32] {
        Sha256::digest(Self::generate_public_key_wire(verifying_key)).into()
    }

    fn get_raw_sha512_fingerprint(verifying_key: &<Self as Key>::VerifyingKey) -> [u8; 64] {
        Sha512::digest(Self::generate_public_key_wire(verifying_key)).into()
    }
}

impl OpenSSHFormatter<Self> for Ed25519Key {
    const OPENSSH_PUBLIC_KEY_SIZE: usize = Self::OPENSSH_PUBLIC_KEY_SIZE;
    const OPENSSH_PRIVATE_KEY_SIZE: usize = Self::OPENSSH_PRIVATE_KEY_SIZE;

    fn format_public_key(
        verifying_key: &<Self as Key>::VerifyingKey,
    ) -> SmallString<[u8; Self::OPENSSH_PUBLIC_KEY_SIZE]> {
        let mut public_key = SmallString::new_const();

        public_key.push_str(Self::SSH_KEY_ALGORITHM_NAME);
        public_key.push(' ');

        let key_wire_base64 = STANDARD_NO_PAD.encode(Self::generate_public_key_wire(verifying_key));
        public_key.push_str(&key_wire_base64);

        public_key
    }

    fn format_private_key(
        signing_key: &<Self as Key>::SigningKey,
        verifying_key: &<Self as Key>::VerifyingKey,
    ) -> SmallString<[u8; Self::OPENSSH_PRIVATE_KEY_SIZE]> {
        let mut private_key = SmallString::new_const();
        let mut private_key_buffer = SmallVec::<[u8; Self::OPENSSH_PRIVATE_KEY_BINARY_SIZE]>::new();

        private_key.push_str(Self::OPENSSH_PEM_HEADER);

        Self::write_private_key_header_section(&mut private_key_buffer)
            .expect("Failed to write OpenSSH private key header section");
        Self::write_private_key_public_key_section(&mut private_key_buffer, verifying_key)
            .expect("Failed to write OpenSSH private key public key section");
        Self::write_private_key_private_key_section(
            &mut private_key_buffer,
            signing_key,
            verifying_key,
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
        writer: &mut W,
        verifying_key: &<Self as Key>::VerifyingKey,
    ) -> std::io::Result<()> {
        let public_key_wire = Self::generate_public_key_wire(verifying_key);

        writer.write_all(&(public_key_wire.len() as u32).to_be_bytes())?;
        writer.write_all(&public_key_wire)?;

        Ok(())
    }

    fn write_private_key_private_key_section<W: std::io::Write>(
        writer: &mut W,
        signing_key: &<Self as Key>::SigningKey,
        verifying_key: &<Self as Key>::VerifyingKey,
    ) -> std::io::Result<()> {
        writer.write_all(&(Self::OPENSSH_PRIVATE_KEY_PRIVATE_SECTION_SIZE as u32).to_be_bytes())?;

        let check_int = rand::random::<u32>();
        writer.write_all(&check_int.to_be_bytes())?;
        writer.write_all(&check_int.to_be_bytes())?;

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
