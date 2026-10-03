//! Ordered assignment of a retailOS seconds/nanoseconds pair.
//!
//! Original: `FUN_08261ec4` @ 0x08261ec4, 20 bytes, ending with `bx lr`
//! at 0x08261ed4; the next real function starts at 0x08261ed8.
//! Whole-image A32 decoding finds two plain inbound BLs (0x08262724,
//! 0x08262778), zero predicated inbound BLs, and zero internal BLs.
//! Both sites in the condition timed-wait body copy the pair at waiter +0x14
//! to/from the caller's pair at +0x08. Load/store seconds first, then
//! load/store nanoseconds. r0 remains the destination, including on return.
//!
//! Deliberate deviation: volatile aligned word accesses preserve the original
//! interleaving for overlapping storage; this is not a snapshot or memmove.
//! No normalization, validation, allocation, or callee seam is introduced.

/// Both pointers must be aligned and valid for two initialized i32 words.
/// Overlap and self-assignment are supported with sequential word semantics.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timespec_copy(dst: *mut i32, src: *const i32) -> *mut i32 {
    dst.write_volatile(src.read_volatile());
    dst.add(1).write_volatile(src.add(1).read_volatile());
    dst
}

#[cfg(test)]
mod tests {
    use super::timespec_copy;

    #[test]
    fn copies_bits_without_normalizing_or_touching_neighbors() {
        for src in [[0, 0], [-1, -1], [i32::MIN, i32::MAX],
                    [i32::MAX, i32::MIN], [7, 1_000_000_000]] {
            let mut dst = [0x12345678, 99, 88, 0x76543210];
            let ptr = unsafe { dst.as_mut_ptr().add(1) };
            unsafe { assert_eq!(timespec_copy(ptr, src.as_ptr()), ptr); }
            assert_eq!(dst, [0x12345678, src[0], src[1], 0x76543210]);
        }
    }

    #[test]
    fn self_assignment_preserves_pair() {
        let mut pair = [i32::MIN, -1];
        let ptr = pair.as_mut_ptr();
        unsafe { assert_eq!(timespec_copy(ptr, ptr), ptr); }
        assert_eq!(pair, [i32::MIN, -1]);
    }

    #[test]
    fn forward_overlap_observes_first_store_before_second_load() {
        let mut words = [11, 22, 33, 44];
        let src = words.as_mut_ptr();
        let dst = unsafe { src.add(1) };
        unsafe { assert_eq!(timespec_copy(dst, src), dst); }
        assert_eq!(words, [11, 11, 11, 44]);
    }

    #[test]
    fn backward_overlap_preserves_both_source_words() {
        let mut words = [11, 22, 33, 44];
        let dst = words.as_mut_ptr();
        unsafe { assert_eq!(timespec_copy(dst, dst.add(1)), dst); }
        assert_eq!(words, [22, 33, 33, 44]);
    }
}
