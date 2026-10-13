//! Word-pair range fill — retailOS `FUN_083ea64c` @ 0x083ea64c.
//! True size: 20 bytes, ending before the independent PUSH at 0x083ea660.
//! Whole-image raw A32 scan: one incoming plain BL at 0x083e0854, zero
//! predicated incoming BLs, and zero outgoing plain or predicated BLs.
//!
//! Compare first with end; when unequal, load both source words before
//! storing either destination word, advance eight bytes, and repeat. The
//! source is reloaded each iteration, preserving even word-shifted overlap.
//! The caller uses this for an in-capacity eight-byte vector insertion.
//! Deliberate deviation: expose the final r0 cursor as a pointer return;
//! Ghidra calls it void, but the raw loop leaves r0 equal to end. No other
//! semantic deviations; LLVM instruction selection need not match ADS.

/// Fills the half-open range with copies of a two-word source.
///
/// # Safety
/// For nonempty bounds, `first` and `end` must delimit writable aligned
/// pairs in one allocation, with end reachable in increments of two words.
/// `source` must provide two readable aligned words throughout the loop.
/// Source may overlap output. Equal bounds dereference no pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_pair_range_fill(
    mut first: *mut u32,
    end: *mut u32,
    source: *const u32,
) -> *mut u32 {
    while first != end {
        let low = source.read();
        let high = source.add(1).read();
        first.write(low);
        first.add(1).write(high);
        first = first.add(2);
    }
    first
}

#[cfg(test)]
mod tests {
    use super::word_pair_range_fill;

    #[test]
    fn empty_bounds_read_nothing_and_return_cursor() {
        unsafe {
            assert_eq!(word_pair_range_fill(core::ptr::null_mut(),
                core::ptr::null_mut(), core::ptr::null()), core::ptr::null_mut());
            let mut word = 0xdead_beefu32;
            let cursor = &mut word as *mut u32;
            assert_eq!(word_pair_range_fill(cursor, cursor, core::ptr::null()), cursor);
            assert_eq!(word, 0xdead_beef);
        }
    }

    #[test]
    fn all_subranges_match_pair_reference_and_preserve_boundaries() {
        let source = [0x8000_0000, 0xffff_ffff];
        for begin in 0..=5 {
            for end in begin..=5 {
                let mut actual = [0x1234_5678u32; 10];
                let mut expected = actual;
                for pair in expected[begin * 2..end * 2].chunks_exact_mut(2) {
                    pair.copy_from_slice(&source);
                }
                unsafe {
                    let base = actual.as_mut_ptr();
                    assert_eq!(word_pair_range_fill(base.add(begin * 2),
                        base.add(end * 2), source.as_ptr()), base.add(end * 2));
                }
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn shifted_overlap_snapshots_both_words_then_reloads_each_iteration() {
        for source_offset in 0..=6 {
            let mut actual = [11u32, 22, 33, 44, 55, 66, 77, 88];
            let mut expected = actual;
            for destination in (1..7).step_by(2) {
                let pair = [expected[source_offset], expected[source_offset + 1]];
                expected[destination] = pair[0];
                expected[destination + 1] = pair[1];
            }
            unsafe {
                let base = actual.as_mut_ptr();
                assert_eq!(word_pair_range_fill(base.add(1), base.add(7),
                    base.add(source_offset)), base.add(7));
            }
            assert_eq!(actual, expected, "source word offset {source_offset}");
        }
    }
}
