//! A fixed-width four-byte copy helper.

/// copy_four_bytes — original: `FUN_0824bf8c` @ **0x0824bf8c** (**36 bytes
/// exactly**, `0x0824bf8c..0x0824bfac`; `0x0824bfb0` opens the distinct
/// four-word sibling).
///
/// Decoding every ARM B/BL word in `osos.dec` verifies **10 direct inbound
/// `bl` call sites**, all unconditional; there are no predicated BL forms or
/// direct tail branches. The nine-instruction body executes four ordered
/// `ldrb`/`strb` pairs from `src` (r1) to `dst` (r0). Each source byte is
/// loaded immediately before its destination store, so later loads observe
/// earlier stores when the ranges overlap.
///
/// Deliberate deviations: none.
///
/// # Safety
/// `src` must be valid for four `u8` reads and `dst` for four `u8` writes.
/// The ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_four_bytes(dst: *mut u8, src: *const u8) {
    dst.write(src.read());
    dst.add(1).write(src.add(1).read());
    dst.add(2).write(src.add(2).read());
    dst.add(3).write(src.add(3).read());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::copy_four_bytes;

    /// Independent model of the four ordered `ldrb`/`strb` instruction pairs.
    fn reference_forward_four_byte_copy(bytes: &mut [u8], dst: usize, src: usize) {
        bytes[dst] = bytes[src];
        bytes[dst + 1] = bytes[src + 1];
        bytes[dst + 2] = bytes[src + 2];
        bytes[dst + 3] = bytes[src + 3];
    }

    #[test]
    fn copies_four_bytes_between_distinct_buffers() {
        let source = [0x12, 0xab, 0x34, 0xcd];
        let mut destination = [0xde, 0xad, 0xbe, 0xef];

        unsafe {
            copy_four_bytes(destination.as_mut_ptr(), source.as_ptr());
        }

        assert_eq!(destination, source);
    }

    #[test]
    fn matches_ordered_instruction_model_for_all_four_byte_overlaps() {
        // Destination offsets -3 through +3 cover every overlap shape. In
        // particular, offsets +1..+3 prove later loads observe earlier stores.
        for dst in 0..=6 {
            let src = 3;
            let initial = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
            let mut expected = initial;
            let mut actual = initial;

            reference_forward_four_byte_copy(&mut expected, dst, src);
            unsafe {
                copy_four_bytes(actual.as_mut_ptr().add(dst), actual.as_ptr().add(src));
            }

            assert_eq!(actual, expected, "dst={dst}");
        }
    }
}
