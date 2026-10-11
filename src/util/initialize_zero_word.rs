//! Initializes an embedded word to zero.

/// `initialize_zero_word` — original `FUN_08058584` @ **0x08058584**.
/// True extent: 12 bytes, ending at the next function at 0x08058590.
/// Verified whole-image inbound calls: two plain BLs (0x0805e0b8,
/// 0x0805e194), zero predicated BLs; zero outgoing calls.
///
/// Raw words are `e3a01000 e5801000 e12fff1e`: write zero to the aligned
/// destination word and return with r0 unchanged. Callers initialize embedded
/// fields at object offsets +0x24 and +0x18 respectively. Their higher-level
/// field meaning is unproven. Deliberate deviation: expose the preserved r0
/// as a pointer return rather than Ghidra's void signature; no NULL guard,
/// extra stores, or object-layout assumptions are introduced.
///
/// # Safety
/// `dst` must be non-NULL, aligned, and writable for one `u32`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn initialize_zero_word(dst: *mut u32) -> *mut u32 {
    dst.write(0);
    dst
}

#[cfg(test)]
mod tests {
    use super::initialize_zero_word;

    #[test]
    fn overwrites_full_word_preserves_neighbors_and_returns_destination() {
        for initial in [0, 1, 0x8000_0000, 0x0123_4567, u32::MAX] {
            let mut words = [0xfeed_face, initial, 0xdead_beef];
            let dst = unsafe { words.as_mut_ptr().add(1) };
            let returned = unsafe { initialize_zero_word(dst) };
            assert_eq!(returned, dst);
            assert_eq!(words, [0xfeed_face, 0, 0xdead_beef]);
        }
    }

    #[test]
    fn initializes_both_real_caller_field_offsets_only() {
        for index in [0x18 / 4, 0x24 / 4] {
            let mut object = [0xa5a5_a5a5; 12];
            let mut expected = object;
            expected[index] = 0;
            unsafe { initialize_zero_word(object.as_mut_ptr().add(index)) };
            assert_eq!(object, expected);
        }
    }
}
