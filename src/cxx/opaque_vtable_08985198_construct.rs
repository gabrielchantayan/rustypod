//! `opaque_vtable_08985198_construct` — retailOS `FUN_0813ece4` @ `0x0813ece4`.
//!
//! True size: 16 bytes: three A32 instructions and literal `0x08985198`
//! at `0x0813ecf0`; the next function begins at `0x0813ecf4` (CMP r0,#0).
//! Ghidra's 12-byte size excludes the literal. Whole-image aligned ARM BL
//! decoding finds two incoming plain BLs at `0x0813ec90` and `0x0813ecc8`,
//! zero predicated BLs, and no outgoing BLs or incoming plain-B tails.
//!
//! Store the opaque base vtable in word 0 and return the object unchanged.
//! Both allocating callers replace the vtable and initialize words 1 and 2
//! through the returned r0. No class identity is inferred from the address.
//! Deliberate deviations: none; Ghidra's void return is corrected using raw
//! register flow. No allocation, null check, or payload initialization.

/// Base vtable literal loaded from `0x0813ecf0`.
pub const OPAQUE_VTABLE_08985198: u32 = 0x0898_5198;

/// # Safety
/// `this` must point to a writable, four-byte-aligned `u32` word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_vtable_08985198_construct(this: *mut u32) -> *mut u32 {
    unsafe { this.write_volatile(OPAQUE_VTABLE_08985198) };
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_only_header_and_preserves_returned_object() {
        for old_header in [0, 1, 0x8000_0000, u32::MAX, OPAQUE_VTABLE_08985198] {
            let mut words = [0x1122_3344, old_header, 0x5566_7788, 0x99aa_bbcc, 0xddee_ff00];
            let object = unsafe { words.as_mut_ptr().add(1) };
            let returned = unsafe { opaque_vtable_08985198_construct(object) };
            assert_eq!(returned, object);
            assert_eq!(words, [0x1122_3344, OPAQUE_VTABLE_08985198,
                               0x5566_7788, 0x99aa_bbcc, 0xddee_ff00]);
        }
    }

    #[test]
    fn accepts_single_word_storage() {
        let mut header = u32::MAX;
        let object = core::ptr::addr_of_mut!(header);
        assert_eq!(unsafe { opaque_vtable_08985198_construct(object) }, object);
        assert_eq!(header, OPAQUE_VTABLE_08985198);
    }
}
