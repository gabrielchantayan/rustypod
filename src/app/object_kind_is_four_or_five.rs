//! `object_kind_is_four_or_five` — `FUN_08280b10` @ load address `0x08280b10`.
//! True extent: `0x08280b10..0x08280b28` (24 bytes); the next function
//! begins with `push {r4, r5, r6, lr}` at `0x08280b28`.
//! Raw A32 decoding verifies two plain inbound BLs at `0x081cbcc4` and
//! `0x081cc75c`, zero predicated inbound BLs, and zero outbound BLs.
//!
//! Loads the unsigned byte at object +0x74, subtracts four in a 32-bit
//! register, and returns one iff the unsigned result is at most one.
//! Thus only kind codes four and five are accepted; their domain meaning
//! is not established. Both callers pass the resolved object in r0.
//! Deliberate deviations: none in behavior; Rust expresses the ARM
//! unsigned wrapping subtraction directly and returns the same u32 0/1.

/// Tests the object's byte discriminator without modifying the object.
///
/// # Safety
/// `object` must reference readable storage through byte +0x74. As in
/// retailOS, NULL is not accepted or guarded.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_kind_is_four_or_five(object: *const u8) -> u32 {
    let kind = unsafe { object.add(0x74).read() };
    ((kind as u32).wrapping_sub(4) <= 1) as u32
}

#[cfg(test)]
mod tests {
    use super::object_kind_is_four_or_five;

    #[test]
    fn accepts_only_four_and_five_for_every_byte_and_base_alignment() {
        for alignment in 0..4 {
            let mut storage = [0xa5u8; 0x78];
            for kind in 0..=u8::MAX {
                storage[alignment + 0x74] = kind;
                let before = storage;
                let result = unsafe {
                    object_kind_is_four_or_five(storage.as_ptr().add(alignment))
                };
                let expected = if kind == 4 || kind == 5 { 1 } else { 0 };
                assert_eq!(result, expected, "kind={kind}, alignment={alignment}");
                assert_eq!(storage, before);
            }
        }
    }

    #[test]
    fn reads_only_the_discriminator_not_neighboring_bytes() {
        let mut object = [0u8; 0x75];
        object[0x73] = 5;
        assert_eq!(unsafe { object_kind_is_four_or_five(object.as_ptr()) }, 0);
        object[0x73] = 0xff;
        object[0x74] = 4;
        assert_eq!(unsafe { object_kind_is_four_or_five(object.as_ptr()) }, 1);
    }
}
