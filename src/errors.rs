#[derive(thiserror::Error, Debug)]
pub enum SshThingError {
    #[error("Key generation error: {0}")]
    KeyGeneration(#[from] KeyError),

    #[error("Keep awake error: {0}")]
    KeepAwake(#[from] KeepAwakeError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum KeyError {
    #[error("Failed to write OpenSSH key part: {0}")]
    WriteKeyPart(#[from] std::io::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum KeepAwakeError {
    #[cfg(target_os = "windows")]
    #[error("Windows API error: {0}")]
    WindowsApi(#[from] windows::core::Error),
}
