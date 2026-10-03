//! Forward copy of a four-word homogeneous fixed-point record.

/// fixed_point_record_copy — original: `FUN_0824c734` @ `0x0824c734`.
/// True extent: 36 bytes (`0x0824c734..0x0824c758`): four alternating
/// aligned word loads/stores, then `bx lr` at 0x0824c754. The next real
/// function is fixed_point_record_construct at 0x0824c758.
/// Whole-image A32 BL decoding finds two inbound plain calls (0x08240b90,
/// 0x08240b9c), zero predicated calls, and zero outbound calls.
///
/// Copies words 0 through 3 in order and returns dst, preserved in r0.
/// The caller copies adjacent 16-byte subobjects; the neighboring constructor
/// establishes a homogeneous fixed-point record with final word 0x10000.
/// No deque field identities are assumed from byte-identical copies elsewhere.
/// Deliberate deviations: volatile accesses preserve the alternating access
/// order, including forward-overlap propagation, and prevent builtin copying.
/// A distinct text section keeps the hook target independently addressable.
/// No NULL guard, snapshot copy, or other semantic deviation.
///
/// # Safety
/// Both pointers must address four aligned u32 words, readable at src and
/// writable at dst. Overlap is allowed; each load observes preceding stores.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.fixed_point_record_copy")]
#[inline(never)]
pub unsafe extern "C" fn fixed_point_record_copy(dst: *mut u32, src: *const u32) -> *mut u32 {
    for word in 0..4 {
        dst.add(word).write_volatile(src.add(word).read_volatile());
    }
    dst
}

#[cfg(test)]
mod tests {
    use super::fixed_point_record_copy;

    #[test]
    fn copies_bit_patterns_and_preserves_neighboring_words() {
        let src = [0x8000_0000, 0, u32::MAX, 0x10000];
        let mut dst = [0xa5a5_5a5a; 6];
        let target = unsafe { dst.as_mut_ptr().add(1) };
        assert_eq!(unsafe { fixed_point_record_copy(target, src.as_ptr()) }, target);
        assert_eq!(dst, [0xa5a5_5a5a, 0x8000_0000, 0, u32::MAX, 0x10000, 0xa5a5_5a5a]);
        assert_eq!(src, [0x8000_0000, 0, u32::MAX, 0x10000]);
    }

    #[test]
    fn overlapping_ranges_follow_retail_forward_word_order() {
        for src_offset in 0..5 {
            for dst_offset in 0..5 {
                let mut actual = [0, 0x8000_0000, 2, u32::MAX, 4, 5, 6, 0x10000];
                let mut expected = actual;
                for word in 0..4 {
                    expected[dst_offset + word] = expected[src_offset + word];
                }
                let base = actual.as_mut_ptr();
                let dst = unsafe { base.add(dst_offset) };
                assert_eq!(unsafe { fixed_point_record_copy(dst, base.add(src_offset)) }, dst);
                assert_eq!(actual, expected, "src={src_offset}, dst={dst_offset}");
            }
        }
    }
}
