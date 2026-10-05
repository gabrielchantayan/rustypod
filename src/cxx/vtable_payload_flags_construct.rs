//! `vtable_payload_flags_construct` — `FUN_081bc95c` @ **0x081bc95c**.
//! True extent: 36 bytes through 0x081bc980: 32 instruction bytes and the
//! four-byte vtable literal at 0x081bc97c. The next function begins with
//! a NULL check and a separate push/return sequence at 0x081bc980.
//! Raw word scanning verifies two inbound plain BLs (0x082973a4,
//! 0x0829742c), zero predicated BLs, and no outbound BLs of either kind.
//!
//! Store the payload word at +4, clear byte +8, set byte +9 to one, then
//! install vtable 0x0898cab4 at +0. Return the original object pointer:
//! r0 is unchanged in the firmware, and both callers consume that result.
//! Callers allocate 12 bytes; bytes +10/+11 remain untouched.
//!
//! Deliberate deviations: none in behavior. Keep payload and vtable as
//! 32-bit target words on hosts too; do not infer a wider class identity
//! or meanings for the two flags from this constructor alone.

/// Vtable address loaded from the literal at 0x081bc97c.
pub const VTABLE_PAYLOAD_FLAGS_VTABLE_ADDRESS: u32 = 0x0898_cab4;

/// Initialize the payload, flag pair, and vtable of a target-layout object.
///
/// # Safety
/// `this` must be four-byte aligned and point to at least 12 writable bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_payload_flags_construct(
    this: *mut u8,
    payload: u32,
) -> *mut u8 {
    unsafe {
        this.cast::<u32>().add(1).write_volatile(payload);
        this.add(8).write_volatile(0);
        this.add(9).write_volatile(1);
        this.cast::<u32>().write_volatile(VTABLE_PAYLOAD_FLAGS_VTABLE_ADDRESS);
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_target_layout_preserving_padding_and_neighbors() {
        for fill in [0u8, 0xa5, 0xff] {
            for payload in [0, 1, 0x8000_0000, 0x1357_9bdf, u32::MAX] {
                let mut words = [u32::from_ne_bytes([fill; 4]); 5];
                let object = unsafe { words.as_mut_ptr().add(1).cast::<u8>() };
                let returned = unsafe { vtable_payload_flags_construct(object, payload) };
                assert_eq!(returned, object);
                // Byte-level reference preserves the untouched allocation tail
                // and catches host pointer-width shifts of the target fields.
                let mut expected = [fill; 20];
                expected[4..8].copy_from_slice(&VTABLE_PAYLOAD_FLAGS_VTABLE_ADDRESS.to_ne_bytes());
                expected[8..12].copy_from_slice(&payload.to_ne_bytes());
                expected[12] = 0;
                expected[13] = 1;
                let actual = unsafe {
                    core::slice::from_raw_parts(words.as_ptr().cast::<u8>(), 20)
                };
                assert_eq!(actual, expected);
            }
        }
    }
}
