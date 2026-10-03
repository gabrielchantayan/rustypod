//! two_word_copy — retailOS `FUN_082724b4` @ 0x082724b4 (20 bytes).
//!
//! Raw words establish 0x082724b4..0x082724c7, five A32 instructions:
//! `ldr r2,[r1]; str r2,[r0]; ldr r1,[r1,#4]; str r1,[r0,#4]; bx lr`.
//! The next independently called function starts at 0x082724c8. Full-image
//! decoding finds two plain inbound BLs (0x08264614, 0x08264660), zero
//! predicated inbound BLs, and zero plain or predicated outbound BLs.
//!
//! Copy two aligned words in load/store order, not as a snapshot: a destination
//! one word above the source propagates the first word into both outputs.
//! Both calls copy embedded draw-state members. Deliberate deviations: none;
//! volatile accesses preserve overlap behavior and prevent bulk-copy lowering.
//! r0 passes through unchanged; the observed callers use no return value.

/// Copies an opaque two-word member.
///
/// # Safety
/// Both pointers must be four-byte aligned and valid for two u32 words, with
/// writable destination storage. Ranges may overlap, including self-copy.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn two_word_copy(destination: *mut u32, source: *const u32) {
    unsafe {
        destination.write_volatile(source.read_volatile());
        destination.add(1).write_volatile(source.add(1).read_volatile());
    }
}

#[cfg(test)]
mod tests {
    use super::two_word_copy;

    #[test]
    fn copies_full_width_words_without_touching_guards_or_source() {
        for source in [[0, u32::MAX], [0x8000_0000, 0x7fff_ffff], [0x1234_5678, 0x9abc_def0]] {
            let mut destination = [0xfeed_face, 0xdead_beef, 0xdead_beef, 0xcafe_babe];
            let before = source;
            unsafe { two_word_copy(destination.as_mut_ptr().add(1), source.as_ptr()) };
            assert_eq!(destination, [0xfeed_face, before[0], before[1], 0xcafe_babe]);
            assert_eq!(source, before);
        }
    }

    #[test]
    fn preserves_instruction_order_for_both_overlap_directions_and_self_copy() {
        for (destination, source, expected) in [
            (2, 1, [0xaaaa_aaaa, 0x1111_1111, 0x1111_1111, 0x1111_1111, 0xbbbb_bbbb]),
            (1, 2, [0xaaaa_aaaa, 0x2222_2222, 0x3333_3333, 0x3333_3333, 0xbbbb_bbbb]),
            (1, 1, [0xaaaa_aaaa, 0x1111_1111, 0x2222_2222, 0x3333_3333, 0xbbbb_bbbb]),
        ] {
            let mut words = [0xaaaa_aaaa, 0x1111_1111, 0x2222_2222, 0x3333_3333, 0xbbbb_bbbb];
            let base = words.as_mut_ptr();
            unsafe { two_word_copy(base.add(destination), base.add(source)) };
            assert_eq!(words, expected);
        }
    }
}
