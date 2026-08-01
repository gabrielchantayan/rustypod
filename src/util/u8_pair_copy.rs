//! A fixed-width byte-pair copy helper.

/// copy_u8_pair — original: `FUN_08046a3c` @ 0x08046a3c (20 bytes).
///
/// Performs two forward, ordered byte loads and stores: it loads `src[0]` and
/// stores it to `dst[0]`, then loads `src[1]` and stores it to `dst[1]`.
/// This is deliberately not a two-byte or generic memory copy: overlapping
/// pairs observe the first store before the second source load, exactly as the
/// original `ldrb`/`strb` instruction pairs do.
///
/// # Safety
/// `src` must be valid for two `u8` reads and `dst` for two `u8` writes. The
/// ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_u8_pair(dst: *mut u8, src: *const u8) {
    dst.write(src.read());
    dst.add(1).write(src.add(1).read());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::copy_u8_pair;

    /// Independent model of the original's two load/store instruction pairs.
    fn reference_forward_pair_copy(bytes: &mut [u8], dst: usize, src: usize) {
        let first = bytes[src];
        bytes[dst] = first;
        let second = bytes[src + 1];
        bytes[dst + 1] = second;
    }

    #[test]
    fn copies_two_bytes_between_distinct_buffers() {
        let source = [0x12, 0xab];
        let mut destination = [0xde, 0xad];

        unsafe {
            copy_u8_pair(destination.as_mut_ptr(), source.as_ptr());
        }

        assert_eq!(destination, source);
    }

    #[test]
    fn matching_two_store_reference_for_all_pair_overlaps() {
        // `dst` immediately before, at, and immediately after `src` covers
        // every pair-overlap layout. In particular dst=src+1 proves the
        // second load observes the first store rather than a preloaded pair.
        for dst in 0..=2 {
            let src = 1;
            let initial = [0x11, 0x22, 0x33, 0x44];
            let mut expected = initial;
            let mut actual = initial;

            reference_forward_pair_copy(&mut expected, dst, src);
            unsafe {
                copy_u8_pair(actual.as_mut_ptr().add(dst), actual.as_ptr().add(src));
            }

            assert_eq!(actual, expected, "dst={dst}, src={src}");
        }
    }
}
