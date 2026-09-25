//! Word-range copy with a nullable destination — original thunk:
//! `thunk_FUN_083e9480` at load address `0x083e9468`.
//!
//! Raw `osos.dec` establishes the thunk's exact four-byte extent: the A32 word
//! `b 0x083e9480` at `0x083e9468`; its branch target enters the range-test at
//! `0x083e9480`, while the loop body starts at `0x083e946c` and `0x083e9490`
//! begins the next function. Full-image A32 decoding finds two inbound plain
//! direct `bl` calls (`0x083e6ac0` and `0x083e6afc`) and zero predicated direct
//! `bl` calls. The thunk has no outbound calls.
//!
//! The branch target compares `source` with `source_end`; while unequal, it
//! copies one target-width word to `destination` when non-null, then advances
//! both cursors and returns the final destination cursor. Deliberate deviation:
//! Rust implements the verified branch target directly rather than retaining
//! the four-byte tail branch; `wrapping_add` preserves the retail null-pointer
//! cursor increment without forming an invalid Rust pointer offset.
//! Volatile word accesses preserve the retail ordered load/store loop and
//! prevent LLVM from replacing it with a libc copy routine.


/// Copies `[source, source_end)` words to `destination` when it is non-null.
///
/// # Safety
///
/// `source` and `source_end` must delimit a forward-reachable word range. A
/// non-null `destination` must identify writable words for that range. Like
/// the retail loop, overlapping ranges are copied forward rather than moved.
/// A null `destination` is only safe for an empty or one-word range: the
/// retail loop advances it to address 4 before its next null check.

#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.word_range_copy_if_destination")]
#[inline(never)]
pub unsafe extern "C" fn word_range_copy_if_destination(
    mut source: *const u32,
    source_end: *const u32,
    mut destination: *mut u32,
) -> *mut u32 {
    while source != source_end {
        if !destination.is_null() {
            destination.write_volatile(source.read_volatile());
        }
        source = source.wrapping_add(1);
        destination = destination.wrapping_add(1);
    }
    destination
}
 
/// `word_range_copy_if_destination_alias_9440` — retailOS
/// `thunk_FUN_083e9458` at load address `0x083e9440` (40 bytes; raw extent
/// `0x083e9440..0x083e9468`). Raw ARM establishes a four-byte `b 0x083e9458`
/// entry, whose target is the range-test loop header; `0x083e9468` starts the
/// next independently linked function. Full-image A32 decoding finds two
/// inbound direct plain `bl` calls, at `0x083e6984` and `0x083e69c0`, and zero
/// predicated direct `bl` calls. The thunk has no outbound calls.
///
/// The target copies the half-open `[source, source_end)` word range forward
/// when the current destination is non-null, advances both cursors, and
/// returns the final destination. Callers use it to copy the two disjoint
/// portions of a growing vector around an inserted word; r3 carries the
/// vector but is never read. Deliberate deviation: this hookable export
/// implements the verified branch target rather than the entry branch.
/// Volatile accesses preserve the ordered retail load/store loop and prevent
/// LLVM from replacing it with a libc copy routine.
///
/// # Safety
///
/// `source` and `source_end` must delimit a forward-reachable word range. A
/// non-null `destination` must identify writable words for that range. Like
/// retailOS, overlapping ranges copy forward; a null destination is safe only
/// for an empty or one-word range.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.word_range_copy_if_destination_alias_9440")]
#[inline(never)]
pub unsafe extern "C" fn word_range_copy_if_destination_alias_9440(
    mut source: *const u32,
    source_end: *const u32,
    mut destination: *mut u32,
) -> *mut u32 {
    while source != source_end {
        if !destination.is_null() {
            destination.write_volatile(source.read_volatile());
        }
        source = source.wrapping_add(1);
        destination = destination.wrapping_add(1);
    }
    destination
}

/// `word_range_copy_if_destination_alias_93f0` — retailOS
/// `thunk_FUN_083e9408` at load address `0x083e93f0` (40 bytes; raw extent
/// `0x083e93f0..0x083e9418`). Raw ARM establishes a four-byte `b 0x083e9408`
/// entry, whose target is the range-test loop header; `0x083e9418` starts the
/// next independently linked function. Full-image A32 decoding finds two
/// inbound direct plain `bl` calls (`0x083e6438`, `0x083e6474`) and zero
/// predicated direct `bl` calls. The thunk has no outbound calls.
///
/// The target copies the half-open `[source, source_end)` word range forward
/// when the current destination is non-null, advances both cursors, and
/// returns the final destination. Deliberate deviation: this hookable export
/// implements the verified branch target rather than the entry branch.
/// Volatile accesses preserve the ordered retail load/store loop and prevent
/// LLVM from replacing it with a libc copy routine.
///
/// # Safety
///
/// `source` and `source_end` must delimit a forward-reachable word range. A
/// non-null `destination` must identify writable words for that range. Like
/// retailOS, overlapping ranges copy forward; a null destination is safe only
/// for an empty or one-word range.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.word_range_copy_if_destination_alias_93f0")]
#[inline(never)]
pub unsafe extern "C" fn word_range_copy_if_destination_alias_93f0(
    mut source: *const u32,
    source_end: *const u32,
    mut destination: *mut u32,
) -> *mut u32 {
    while source != source_end {
        if !destination.is_null() {
            destination.write_volatile(source.read_volatile());
        }
        source = source.wrapping_add(1);
        destination = destination.wrapping_add(1);
    }
    destination
}



#[cfg(test)]
mod tests {
    use super::{
        word_range_copy_if_destination, word_range_copy_if_destination_alias_93f0,
        word_range_copy_if_destination_alias_9440,
    };
    #[test]
    fn alias_93f0_copies_and_preserves_retail_cursor_rules() {
        let mut words = [0x1111_1111_u32, 0x2222_2222, 0x3333_3333, 0x4444_4444];

        let copied_end = unsafe {
            word_range_copy_if_destination_alias_93f0(
                words.as_ptr(),
                words.as_ptr().add(3),
                words.as_mut_ptr().add(1),
            )
        };
        let null_end = unsafe {
            word_range_copy_if_destination_alias_93f0(
                words.as_ptr(),
                words.as_ptr().add(1),
                core::ptr::null_mut(),
            )
        };

        assert_eq!(words, [0x1111_1111; 4]);
        assert_eq!(copied_end, unsafe { words.as_mut_ptr().add(4) });
        assert_eq!(null_end as usize, 4);
    }

    #[test]
    fn copies_words_and_returns_the_destination_cursor() {
        let source = [0x1357_9bdf, 0x2468_ace0, 0xdead_beef];
        let mut destination = [0_u32; 5];

        let end = unsafe {
            word_range_copy_if_destination(
                source.as_ptr(),
                source.as_ptr().add(3),
                destination.as_mut_ptr().add(1),
            )
        };

        assert_eq!(destination, [0, source[0], source[1], source[2], 0]);
        assert_eq!(end, unsafe { destination.as_mut_ptr().add(4) });
    }

    #[test]
    fn leaves_destination_unchanged_for_an_empty_range() {
        let source = [0x1111_1111_u32];
        let mut destination = [0x2222_2222_u32];

        let end = unsafe {
            word_range_copy_if_destination(source.as_ptr(), source.as_ptr(), destination.as_mut_ptr())
        };

        assert_eq!(destination, [0x2222_2222]);
        assert_eq!(end, destination.as_mut_ptr());
    }
    #[test]
    fn advances_a_null_destination_once_without_writing() {
        let source = [0x1111_1111_u32];

        let end = unsafe {
            word_range_copy_if_destination(source.as_ptr(), source.as_ptr().add(1), core::ptr::null_mut())
        };

        assert_eq!(end as usize, 4);
    }

    #[test]
    fn preserves_the_retail_forward_overlap_order() {
        let mut words = [0x1111_1111_u32, 0x2222_2222, 0x3333_3333, 0x4444_4444];

        unsafe { word_range_copy_if_destination(words.as_ptr(), words.as_ptr().add(3), words.as_mut_ptr().add(1)) };

        assert_eq!(words, [0x1111_1111; 4]);
    }

    #[test]
    fn alias_9440_copies_the_half_open_range_and_returns_the_cursor() {
        let source = [0x1357_9bdf, 0x2468_ace0, 0xdead_beef];
        let mut destination = [0_u32; 5];

        let end = unsafe {
            word_range_copy_if_destination_alias_9440(
                source.as_ptr(),
                source.as_ptr().add(3),
                destination.as_mut_ptr().add(1),
            )
        };

        assert_eq!(destination, [0, source[0], source[1], source[2], 0]);
        assert_eq!(end, unsafe { destination.as_mut_ptr().add(4) });
    }

    #[test]
    fn alias_9440_empty_range_and_null_destination_follow_retail_cursor_rules() {
        let source = [0x1111_1111_u32];
        let mut destination = [0x2222_2222_u32];

        let empty = unsafe {
            word_range_copy_if_destination_alias_9440(
                source.as_ptr(),
                source.as_ptr(),
                destination.as_mut_ptr(),
            )
        };
        let null = unsafe {
            word_range_copy_if_destination_alias_9440(
                source.as_ptr(),
                source.as_ptr().add(1),
                core::ptr::null_mut(),
            )
        };

        assert_eq!(destination, [0x2222_2222]);
        assert_eq!(empty, destination.as_mut_ptr());
        assert_eq!(null as usize, 4);
    }

    #[test]
    fn alias_9440_preserves_the_retail_forward_overlap_order() {
        let mut words = [0x1111_1111_u32, 0x2222_2222, 0x3333_3333, 0x4444_4444];

        unsafe {
            word_range_copy_if_destination_alias_9440(
                words.as_ptr(),
                words.as_ptr().add(3),
                words.as_mut_ptr().add(1),
            )
        };

        assert_eq!(words, [0x1111_1111; 4]);
    }
}
