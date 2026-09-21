//! Decoder cached-range lookup — original: `FUN_082e1ed0` @ `0x082e1ed0`.
//!
//! Raw `osos.dec` establishes the exact 164-byte body
//! `0x082e1ed0..0x082e1f73`; `0x082e1f74` starts the next independently linked
//! function with `push {r4-r6,lr}`. The body has zero plain `bl` instructions
//! and zero predicated `bl` instructions: its cache-miss path is a tail branch
//! to `FUN_082e1d98` at `0x082e1d98`.
//!
//! It searches the optional packed `{start, length}` range table at
//! `stream + 0x20`. A containing range supplies as many requested units as it
//! can; its successor's start is returned when the request crosses a range
//! boundary. An absent table, sentinel, or miss tail-dispatches to the decoder
//! range helper.
//!
//! Deliberate deviations: the tail branch is represented by the existing
//! `DECODER_NEXT_RANGE` dispatch seam, so host tests can exercise its callers;
//! table addresses remain target-width `u32` words on 64-bit hosts.

use core::ptr;

use super::range_segments::DECODER_NEXT_RANGE;

const RANGE_TABLE_WORD: usize = 0x20 / 4;

/// Looks up a requested decoder range and writes the next range start.
///
/// `stream` must point to a target-width object whose `+0x20` word is either
/// zero or a readable, zero-length-terminated `{start, length}` table.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn decoder_range_lookup(
    stream: *const u32,
    decoder: u32,
    start: u32,
    next_start: *mut u32,
    units: u32,
) -> u32 {
    let table = unsafe { stream.add(RANGE_TABLE_WORD).read() } as usize as *const u32;
    if !table.is_null() {
        let mut entry = table;
        loop {
            let length = unsafe { entry.add(1).read() };
            if length == 0 {
                break;
            }
            let range_start = unsafe { entry.read() };
            if range_start <= start && start < range_start.wrapping_add(length) {
                let remaining = length - (start - range_start);
                let next = if units < remaining {
                    start.wrapping_add(units)
                } else if unsafe { entry.add(3).read() } == 0 {
                    range_start.wrapping_add(length).wrapping_sub(1)
                } else {
                    unsafe { entry.add(2).read() }
                };
                unsafe { next_start.write(next) };
                return remaining.min(units);
            }
            entry = unsafe { entry.add(2) };
        }
    }

    let fallback = unsafe { ptr::read_volatile(ptr::addr_of!(DECODER_NEXT_RANGE)) };
    unsafe { fallback(decoder, start, next_start, units) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    fn with_table(test: impl FnOnce(*mut u32)) {
        let Some(slab) = try_map_u32_slab(hints::DECODER_RANGE_LOOKUP, 0x1000) else {
            assert!(note_missing_u32_fixture("h264/decoder_range_lookup"));
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            test(slab.cast());
        }
    }

    #[test]
    fn limits_a_request_to_the_containing_cached_range() {
        with_table(|slab| unsafe {
            let table = slab.add(0x40);
            table.write(10);
            table.add(1).write(5);
            table.add(2).write(0);
            table.add(3).write(0);
            slab.add(RANGE_TABLE_WORD).write(table as usize as u32);
            let mut next = 0;
            assert_eq!(decoder_range_lookup(slab, 0, 12, &mut next, 2), 2);
            assert_eq!(next, 14);
        });
    }

    #[test]
    fn crosses_to_the_following_cached_range_or_terminal_end() {
        with_table(|slab| unsafe {
            let table = slab.add(0x40);
            table.write(10);
            table.add(1).write(5);
            table.add(2).write(50);
            table.add(3).write(2);
            table.add(4).write(0);
            table.add(5).write(0);
            slab.add(RANGE_TABLE_WORD).write(table as usize as u32);
            let mut next = 0;
            assert_eq!(decoder_range_lookup(slab, 0, 12, &mut next, 5), 3);
            assert_eq!(next, 50);

            table.add(3).write(0);
            assert_eq!(decoder_range_lookup(slab, 0, 13, &mut next, 8), 2);
            assert_eq!(next, 14);
        });
    }
}
