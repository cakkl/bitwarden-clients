//! Foreground activation that Electron does not expose.
//!
//! On Windows `BrowserWindow.focus()` and `app.focus()` are only requests: the OS refuses
//! foreground activation for a background process, so a prompt can be visible on top while
//! keystrokes still go to the window the user came from.

#[napi]
pub mod window_focus {
    /// Brings the window identified by `handle` to the foreground.
    ///
    /// `handle` is the `Buffer` from Electron's `getNativeWindowHandle()`; on Windows that is the
    /// window's `HWND`. A no-op elsewhere, where `focus()` already works.
    #[allow(clippy::unused_async)] // FIXME: Remove unused async!
    #[napi]
    pub async fn force_foreground(handle: napi::bindgen_prelude::Buffer) -> napi::Result<()> {
        #[cfg(target_os = "windows")]
        {
            let raw = handle_to_isize(handle.as_ref());
            if raw == 0 {
                return Err(napi::Error::from_reason("invalid window handle"));
            }
            biometric::windows_focus::force_foreground(raw);
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = handle;
        }

        Ok(())
    }

    /// Reads the `HWND` out of Electron's buffer, which is as wide as a pointer.
    #[cfg(target_os = "windows")]
    fn handle_to_isize(bytes: &[u8]) -> isize {
        match bytes.len() {
            8 => isize::from_ne_bytes(bytes.try_into().expect("length checked")),
            4 => u32::from_ne_bytes(bytes.try_into().expect("length checked")) as isize,
            _ => 0,
        }
    }
}
