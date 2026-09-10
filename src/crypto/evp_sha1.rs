//! OpenSSL's `EVP_sha1` descriptor getter from Apple's retailOS copy.
//!
//! `evp_sha1` — original: `FUN_0804b214` @ 0x0804b214, 8 instruction
//! bytes plus its four-byte literal pool at 0x0804b21c. Raw ARM decode:
//!
//! ```text
//! 0804b214:  ldr r0,[pc]    ; 0x08906620
//! 0804b218:  bx  lr
//! ```
//!
//! The next separately entered function starts at 0x0804b220, so the pool
//! belongs to this getter rather than its successor. A scan decoding every
//! ARM B/BL word in `osos.dec` found 11 direct call sites: all are
//! unconditional `bl`; there are no predicated calls and no tail `b` sites.
//!
//! # Body
//!
//! Returns the statically allocated `EVP_MD` descriptor for SHA-1. The
//! callers hand this descriptor to `EVP_DigestInit_ex` / `EVP_DigestUpdate`
//! paths and request its 20-byte digest output.
//!
//! # Deliberate host deviation
//!
//! The firmware's descriptor is a fixed target address in its RAM image.
//! Returning that numeric address on the host preserves the ABI and can be
//! tested without dereferencing memory that only exists on the iPod.

use super::evp_digest_update::EvpMd;

/// The SHA-1 `EVP_MD` descriptor literal loaded by the firmware getter.
pub const EVP_SHA1_DESCRIPTOR_ADDRESS: usize = 0x0890_6620;

/// `EVP_sha1()` — original: `FUN_0804b214` @ 0x0804b214 (8 bytes).
///
/// Returns the SHA-1 `EVP_MD` descriptor at its fixed firmware address.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn evp_sha1() -> *const EvpMd {
    EVP_SHA1_DESCRIPTOR_ADDRESS as *const EvpMd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_the_sha1_descriptor_literal() {
        assert_eq!(evp_sha1() as usize, EVP_SHA1_DESCRIPTOR_ADDRESS);
    }
}
