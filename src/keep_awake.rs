use crate::errors::KeepAwakeError;

pub trait KeepAwake {
    fn new(reason: &str) -> Result<Self, KeepAwakeError>
    where
        Self: Sized;

    fn prevent_sleep(&mut self) -> Result<(), KeepAwakeError>;
    fn allow_sleep(&mut self) -> Result<(), KeepAwakeError>;
}

pub struct SystemKeepAwake {
    #[cfg(target_os = "windows")]
    inner: Option<windows::PowerRequest>,
    #[cfg(not(target_os = "windows"))]
    inner: (),
}

impl KeepAwake for SystemKeepAwake {
    #[cfg(target_os = "windows")]
    fn new(reason: &str) -> Result<Self, KeepAwakeError> {
        let inner = Some(windows::PowerRequest::new(reason)?);

        Ok(Self { inner })
    }

    #[cfg(not(target_os = "windows"))]
    fn new(_reason: &str) -> Result<Self, KeepAwakeError> {
        Ok(Self { inner: () })
    }

    #[cfg(target_os = "windows")]
    fn prevent_sleep(&mut self) -> Result<(), KeepAwakeError> {
        if let Some(inner) = &mut self.inner {
            inner.prevent_sleep()?;
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn prevent_sleep(&mut self) -> Result<(), KeepAwakeError> {
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn allow_sleep(&mut self) -> Result<(), KeepAwakeError> {
        if let Some(inner) = &mut self.inner {
            inner.allow_sleep()?;
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn allow_sleep(&mut self) -> Result<(), KeepAwakeError> {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use windows::{
        Win32::{
            self,
            Foundation::CloseHandle,
            System::{
                Power::PowerRequestExecutionRequired,
                SystemServices::POWER_REQUEST_CONTEXT_VERSION,
                Threading::{
                    POWER_REQUEST_CONTEXT_SIMPLE_STRING, REASON_CONTEXT, REASON_CONTEXT_0,
                },
            },
        },
        core::PWSTR,
    };

    use crate::errors::KeepAwakeError;
    use crate::keep_awake::KeepAwake;

    pub struct PowerRequest {
        handle: Win32::Foundation::HANDLE,
        sleep_active: bool,
    }

    impl KeepAwake for PowerRequest {
        fn new(reason: &str) -> Result<Self, KeepAwakeError> {
            unsafe {
                let mut reason_wide: Vec<u16> =
                    reason.encode_utf16().chain(std::iter::once(0)).collect();
                let context = REASON_CONTEXT {
                    Flags: POWER_REQUEST_CONTEXT_SIMPLE_STRING,
                    Version: POWER_REQUEST_CONTEXT_VERSION,
                    Reason: REASON_CONTEXT_0 {
                        SimpleReasonString: PWSTR(reason_wide.as_mut_ptr()),
                    },
                };
                let handle = Win32::System::Power::PowerCreateRequest(&context)
                    .map_err(KeepAwakeError::WindowsApi)?;

                Ok(Self {
                    handle,
                    sleep_active: false,
                })
            }
        }

        fn prevent_sleep(&mut self) -> Result<(), KeepAwakeError> {
            if !self.sleep_active {
                unsafe {
                    Win32::System::Power::PowerSetRequest(
                        self.handle,
                        PowerRequestExecutionRequired,
                    )
                    .map_err(KeepAwakeError::WindowsApi)?;
                }
                self.sleep_active = true;
            }

            Ok(())
        }

        fn allow_sleep(&mut self) -> Result<(), KeepAwakeError> {
            if self.sleep_active {
                unsafe {
                    Win32::System::Power::PowerClearRequest(
                        self.handle,
                        PowerRequestExecutionRequired,
                    )
                    .map_err(KeepAwakeError::WindowsApi)?;
                }
                self.sleep_active = false;
            }

            Ok(())
        }
    }

    impl Drop for PowerRequest {
        fn drop(&mut self) {
            if self.sleep_active {
                let _ = self.allow_sleep();

                unsafe {
                    let _ = CloseHandle(self.handle);
                }
            }
        }
    }
}

// TODO: Implement for Linux (and macOS?)
