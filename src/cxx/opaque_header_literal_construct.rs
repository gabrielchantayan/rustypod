//! `opaque_header_literal_construct` — original: `FUN_0813eec4` @
//! **0x0813eec4** (16 bytes: three instruction words through 0x0813eecc plus
//! the four-byte literal-pool word at 0x0813eed0; Ghidra reports only the
//! 12 instruction bytes).
//!
//! # Extent and reachability, binary-verified
//!
//! The next separately linked function begins at 0x0813eed4. Decoding every
//! ARM B/BL immediate in `work/firmware/osos.dec` finds exactly six direct
//! call sites, all unconditional `bl`: 0x0827be64, 0x0827bea4, 0x0827bee8,
//! 0x0827bf1c, 0x0827bf44, and 0x083d5854. There are no predicated `bl` or
//! plain-`b` tail-call sites. The function address occurs in no aligned data
//! word, so it is statically called rather than dispatched virtually.
//!
//! # Algorithm
//!
//! Store literal `0x089851dc` at `this + 0x00`, then return `this` unchanged.
//! The ARM body has no argument, null, or alignment guard.
//!
//! # Deliberate deviations
//!
//! None. The literal points into opaque data whose first words do not decode as
//! function pointers, so this port deliberately names neither a class nor a
//! vtable identity.

/// The opaque literal-pool word at 0x0813eed0.
pub const OPAQUE_HEADER_LITERAL: u32 = 0x0898_51dc;

/// Stores the opaque header literal at `this + 0x00` and returns `this`.
///
/// # Safety
///
/// `this` must point to at least four writable, four-byte-aligned bytes. The
/// original ARM `str` dereferences it without a null or alignment check.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_header_literal_construct")]
#[inline(never)]
pub unsafe extern "C" fn opaque_header_literal_construct(this: *mut u8) -> *mut u8 {
    unsafe { this.cast::<u32>().write_volatile(OPAQUE_HEADER_LITERAL) };
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(4))]
    struct AlignedBytes([u8; 12]);

    #[test]
    fn installs_the_literal_and_returns_this() {
        let mut storage = AlignedBytes([0xa5; 12]);
        let this = unsafe { storage.0.as_mut_ptr().add(4) };

        let returned = unsafe { opaque_header_literal_construct(this) };

        assert_eq!(returned, this);
        assert_eq!(unsafe { this.cast::<u32>().read() }, OPAQUE_HEADER_LITERAL);
    }

    #[test]
    fn overwrites_only_the_header_word() {
        let mut storage = AlignedBytes([0x3c; 12]);
        let this = unsafe { storage.0.as_mut_ptr().add(4) };
        unsafe { this.cast::<u32>().write(0xdead_beef) };

        unsafe { opaque_header_literal_construct(this) };

        assert_eq!(&storage.0[..4], &[0x3c; 4]);
        assert_eq!(unsafe { this.cast::<u32>().read() }, OPAQUE_HEADER_LITERAL);
        assert_eq!(&storage.0[8..], &[0x3c; 4]);
    }
}
