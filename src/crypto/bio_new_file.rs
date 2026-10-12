//! OpenSSL file BIO factory disabled by retailOS.
//!
//! `FUN_0803d5c0` @ `0x0803d5c0`: true extent **48 bytes** through
//! `0x0803d5f0` (20 instruction bytes and 28 bytes of inline diagnostic).
//! Raw ARM words: e92d4010 e28f0008 ebffc831 e3a00000 e8bd8010.
//! Two incoming plain BL sites (`0x08043760`, `0x080eee10`), no predicated
//! BL; one outgoing plain BL (`0x0803d5c8`) to printf @ `0x0802f694`.
//!
//! Prints `BIO_new_file() stub called\n`, ignores the filename and mode,
//! and returns NULL regardless of the diagnostic's result. No file is opened.
//!
//! Deliberate deviations: calls the existing Rust printf with an explicit
//! empty va_list; the literal contains no conversions, so no argument is read.
//! That port currently discards semihosting output and has a stub engine;
//! this function retains its diagnostic call rather than adding another seam.

//!
//! Verification: 15,784 host tests pass; ARM release builds. match.py exits
//! 1 with a structural diff: LLVM inlines printf, calls PRINTF_ENGINE via
//! BLX with stdout and an empty va_list, then returns zero. The original
//! diagnostic BL and NULL return survive semantically; no input loads appear.
//! An isolated actual-source smoke with a diagnostic boundary returning -1
//! prints the message and returns NULL for invalid input pointers.
use crate::crypto::bio_ctrl::Bio;
use crate::printf::printf_api::printf;

/// Disabled file factory. Both pointers are ignored, even when NULL or invalid.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bio_new_file(_filename: *const u8, _mode: *const u8) -> *mut Bio {
    unsafe { printf(b"BIO_new_file() stub called\n\0".as_ptr(), core::ptr::null()) };
    core::ptr::null_mut()
}
