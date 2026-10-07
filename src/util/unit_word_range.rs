//! Construct a unit range of two zero-extended word endpoints.
//!
//! Original `FUN_08158b68` at 0x08158b68, 56 bytes, extent
//! [0x08158b68, 0x08158ba0), followed by an independent PUSH prologue.
//! Whole-image aligned A32 decoding finds two plain incoming BLs at
//! 0x08127778 and 0x0829b1fc, zero predicated incoming BLs, one plain
//! outgoing BL at 0x08158b88 to 0x08158cb0, and zero predicated outgoing BLs.
//! Snapshot the input word, increment modulo 2^32, construct two pairs
//! (start, 0) and (end, 0), then copy all four words to the destination.
//! The raw callee uses the ported copy_u32_pair at 0x081b4e10 twice;
//! its returned destination pointer confirms the four-word layout.
//! Deliberate deviation: expand this verified pure construction instead of
//! retaining the temporary stack object and resident constructor call.
//! Volatile aligned accesses preserve the input snapshot before output stores.

/// # Safety
/// `start` must permit one aligned u32 read and `destination` four aligned
/// u32 writes. Input and output may overlap. No validation is performed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn unit_word_range(destination: *mut u32, start: *const u32) {
    let first = start.read_volatile();
    let end = first.wrapping_add(1);
    destination.write_volatile(first);
    destination.add(1).write_volatile(0);
    destination.add(2).write_volatile(end);
    destination.add(3).write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::unit_word_range;

    #[test]
    fn endpoints_zero_extend_and_increment_wraps_at_word_width() {
        for start in [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, u32::MAX] {
            let mut output = [0xdead_beef; 6];
            unsafe { unit_word_range(output.as_mut_ptr().add(1), &start) };
            let end = ((start as u64 + 1) & 0xffff_ffff) as u32;
            assert_eq!(output, [0xdead_beef, start, 0, end, 0, 0xdead_beef]);
        }
    }

    #[test]
    fn snapshots_input_in_every_overlapping_output_word() {
        for source in 1..=4 {
            let mut words = [0xfeed_face, 10, 20, 30, u32::MAX, 0xcafe_babe];
            let first = words[source];
            unsafe { unit_word_range(words.as_mut_ptr().add(1), words.as_ptr().add(source)) };
            assert_eq!(words, [0xfeed_face, first, 0, first.wrapping_add(1), 0, 0xcafe_babe]);
        }
    }
}
