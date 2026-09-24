//! FixA magic validation.
//!
//! `validate_fixa_magic` — retailOS `FUN_080d21d0` @ `0x080d21d0` (36 bytes,
//! `0x080d21d0..0x080d21f4`; `0x080d21f4` is its `FixA` literal pool and the
//! next independently linked function begins at `0x080d21f8`).
//!
//! A complete ARM B/BL decode of `osos.dec` finds **3 direct `bl` call sites**,
//! all unconditional: `0x08048ec4`, `0x08048f50`, and `0x0805de24`; there are
//! no predicated `bl` calls. The function returns one only for a non-NULL
//! owner whose first target word is the literal `0x46697841` (`FixA`), and
//! otherwise returns zero.
//!
//! Deliberate deviation: the literal-pool load is expressed as a named Rust
//! constant; the observable NULL guard, word load, comparison, and `u32`
//! boolean result are unchanged.

const FIXA_MAGIC: u32 = 0x4669_7841;

/// Returns whether `owner` begins with the observed FixA magic word.
///
/// # Safety
///
/// A non-NULL `owner` must point to at least one readable, aligned target word.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.validate_fixa_magic")]
#[inline(never)]
pub unsafe extern "C" fn validate_fixa_magic(owner: *const u32) -> u32 {
    if owner.is_null() {
        return 0;
    }

    (unsafe { owner.read_volatile() } == FIXA_MAGIC) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_null_and_wrong_magic_but_accepts_fixa_magic() {
        let matching = [FIXA_MAGIC, 0xffff_ffff];
        let wrong = [0x4669_7840];

        unsafe {
            assert_eq!(validate_fixa_magic(core::ptr::null()), 0);
            assert_eq!(validate_fixa_magic(wrong.as_ptr()), 0);
            assert_eq!(validate_fixa_magic(matching.as_ptr()), 1);
        }
    }
}
