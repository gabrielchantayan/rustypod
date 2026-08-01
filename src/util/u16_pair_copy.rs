//! A fixed-width halfword-pair copy helper.

/// copy_u16_pair — original: `FUN_08046a28` @ 0x08046a28 (20 bytes).
///
/// Performs two forward, ordered 16-bit loads and stores: it loads `src[0]`
/// and stores it to `dst[0]`, then loads `src[1]` and stores it to `dst[1]`.
/// This is deliberately not a four-byte or generic memory copy: overlapping
/// pairs observe the first store before the second source load, exactly as the
/// original `ldrh`/`strh` instruction pairs do.
///
/// # Safety
/// `src` must be valid for two aligned `u16` reads and `dst` for two aligned
/// `u16` writes. The ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_u16_pair(dst: *mut u16, src: *const u16) {
    dst.write(src.read());
    dst.add(1).write(src.add(1).read());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::copy_u16_pair;

    /// Independent model of the original's two load/store instruction pairs.
    fn reference_forward_pair_copy(words: &mut [u16], dst: usize, src: usize) {
        let first = words[src];
        words[dst] = first;
        let second = words[src + 1];
        words[dst + 1] = second;
    }

    #[test]
    fn copies_two_words_between_distinct_buffers() {
        let source = [0x1234, 0xabcd];
        let mut destination = [0xdead, 0xbeef];

        unsafe {
            copy_u16_pair(destination.as_mut_ptr(), source.as_ptr());
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
            let initial = [0x1111, 0x2222, 0x3333, 0x4444];
            let mut expected = initial;
            let mut actual = initial;

            reference_forward_pair_copy(&mut expected, dst, src);
            unsafe {
                copy_u16_pair(actual.as_mut_ptr().add(dst), actual.as_ptr().add(src));
            }

            assert_eq!(actual, expected, "dst={dst}, src={src}");
        }
    }
}
