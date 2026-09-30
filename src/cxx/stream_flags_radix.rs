//! `stream_flags_radix` — retailOS `FUN_082a7730` @ load address 0x082a7730.
//!
//! True extent: 68 bytes, 0x082a7730..0x082a7774 (64 instruction bytes
//! followed by the 0x0000804a mask literal). The next independently called
//! function starts at 0x082a7774. Raw aligned A32 decoding verifies two
//! inbound plain BLs (0x083b64ec, 0x083b6980), zero predicated inbound BLs,
//! and zero outbound plain or predicated BLs.
//!
//! Read the aligned flags word at stream +4, mask with 0x804a, and return
//! octal, decimal, hexadecimal, or binary radix for exactly one base flag.
//! Missing or conflicting base flags return zero. The numeric-input callers
//! store this result as their parser radix; one later defaults zero to ten.
//! Deliberate deviations: none in behavior; Rust expresses the predicated
//! comparisons as a match. No concrete stream class layout is assumed.

/// Returns the radix selected by a stream's target-width formatting flags.
///
/// # Safety
/// `stream_words.add(1)` must point to an initialized, readable aligned u32.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_flags_radix(stream_words: *const u32) -> u32 {
    match unsafe { stream_words.add(1).read() } & 0x804a {
        0x40 => 8,
        0x02 => 10,
        0x08 => 16,
        0x8000 => 2,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_base_flag_combination_and_ignored_bit() {
        let bits = [0x40, 0x02, 0x08, 0x8000];
        let radices = [8, 10, 16, 2];
        for subset in 0u32..16 {
            let mut flags = 0;
            for index in 0..4 {
                if subset & (1 << index) != 0 { flags |= bits[index]; }
            }
            let expected = if subset.count_ones() == 1 {
                radices[subset.trailing_zeros() as usize]
            } else {
                0
            };
            for ignored in core::iter::once(0).chain(core::iter::once(!0x804a))
                .chain((0..32).map(|bit| (1u32 << bit) & !0x804a)) {
                let words = [!flags, flags | ignored, 0xdead_beef];
                assert_eq!(unsafe { stream_flags_radix(words.as_ptr()) }, expected,
                    "flags={:#x}", flags | ignored);
                assert_eq!(words, [!flags, flags | ignored, 0xdead_beef]);
            }
        }
    }
}
