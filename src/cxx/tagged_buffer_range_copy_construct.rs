//! Tagged-buffer range copy construction — retailOS `FUN_083e8e44` at load
//! address `0x083e8e44` (56 bytes, `0x083e8e44..0x083e8e7c`).
//!
//! Raw `osos.dec` decoding establishes the following `push {r4,r5,r6,lr}` at
//! `0x083e8e7c` as the next function boundary. It finds two inbound plain
//! direct `bl` calls (`0x083e435c`, `0x083e4438`) and no predicated inbound
//! calls. The body has no plain `bl` and one predicated `blne` to unported
//! `FUN_0827c18c` at `0x0827c18c`.
//!
//! The function walks 0x10-byte elements over `[first, last)`. A non-NULL
//! output cursor is copy-constructed from each source element, then both
//! cursors advance by 0x10; it returns the advanced output cursor. Loop
//! termination is cursor equality, not ordering.
//!
//! Deliberate deviation: `FUN_0827c18c` has no `names.yaml` entry, so this
//! port inlines its raw, 68-byte observed operation rather than inventing an
//! unverified seam: set destination state to empty, clear target words +8/+c,
//! release it (therefore no-op), then copy source byte +0 and words +8/+c.
//! Target pointer fields remain 32-bit words on hosts.

use crate::cxx::tagged_buffer_release::{
    tagged_buffer_release, TAGGED_BUFFER_EMPTY, TAGGED_BUFFER_ALLOCATION_WORD,
};

const TAGGED_BUFFER_TRAILING_WORD: usize = 3;

unsafe fn tagged_buffer_copy_construct(destination: *mut u8, source: *const u8) {
    destination.write_volatile(TAGGED_BUFFER_EMPTY);
    let destination_words = destination.cast::<u32>();
    destination_words
        .add(TAGGED_BUFFER_ALLOCATION_WORD)
        .write_volatile(0);
    destination_words
        .add(TAGGED_BUFFER_TRAILING_WORD)
        .write_volatile(0);
    tagged_buffer_release(destination);

    destination.write_volatile(source.read_volatile());
    destination_words
        .add(TAGGED_BUFFER_ALLOCATION_WORD)
        .write_volatile(
            source
                .cast::<u32>()
                .add(TAGGED_BUFFER_ALLOCATION_WORD)
                .read_volatile(),
        );
    destination_words
        .add(TAGGED_BUFFER_TRAILING_WORD)
        .write_volatile(source.cast::<u32>().add(TAGGED_BUFFER_TRAILING_WORD).read_volatile());
}

/// Copy-constructs target-layout tagged buffers from `[first, last)` to `output`.
///
/// # Safety
///
/// `first` and `last` must delimit a forward-reachable range of readable,
/// 0x10-byte tagged-buffer elements. A non-NULL `output` must be writable for
/// the same number of elements. The retail loop copies forward, so overlapping
/// ranges are not moved.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tagged_buffer_range_copy_construct(
    mut first: *const u8,
    last: *const u8,
    mut output: *mut u8,
) -> *mut u8 {
    while first != last {
        if !output.is_null() {
            tagged_buffer_copy_construct(output, first);
        }
        first = first.wrapping_add(0x10);
        output = output.wrapping_add(0x10);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_the_observed_target_words_and_strides_both_cursors() {
        let source = [0x1122_3344u32, 0x5566_7788, 0x99aa_bbcc, 0xddee_ff00];
        let mut destination = [0xa5a5_a5a5u32; 4];
        let output = destination.as_mut_ptr().cast::<u8>();

        let returned = unsafe {
            tagged_buffer_range_copy_construct(
                source.as_ptr().cast::<u8>(),
                source.as_ptr().cast::<u8>().add(0x10),
                output,
            )
        };

        assert_eq!(returned, unsafe { output.add(0x10) });
        assert_eq!(destination[0] & 0xff, source[0] & 0xff);
        assert_eq!(destination[1], 0xa5a5_a5a5, "bytes +1..+7 are not copied");
        assert_eq!(destination[2], source[2]);
        assert_eq!(destination[3], source[3]);
    }

    #[test]
    fn empty_and_null_output_preserve_the_raw_loop_guards() {
        let source = [0u32; 4];
        assert_eq!(
            unsafe {
                tagged_buffer_range_copy_construct(
                    source.as_ptr().cast::<u8>(),
                    source.as_ptr().cast::<u8>(),
                    0x1234usize as *mut u8,
                )
            },
            0x1234usize as *mut u8,
            "empty ranges do not dereference either cursor"
        );
        assert_eq!(
            unsafe {
                tagged_buffer_range_copy_construct(
                    core::ptr::null(),
                    0x10usize as *const u8,
                    core::ptr::null_mut(),
                )
            },
            0x10usize as *mut u8,
            "NULL output skips construction but advances by one element"
        );
    }
}
