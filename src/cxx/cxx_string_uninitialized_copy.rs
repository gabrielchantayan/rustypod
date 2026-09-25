//! COW string uninitialized copy — retailOS `FUN_083e9390` at load address
//! `0x083e9390` (56 bytes; true extent `0x083e9390..0x083e93c8`).
//!
//! Raw `osos.dec` decoding finds two inbound plain direct `bl` calls
//! (`0x083e5a30`, `0x083e5a6c`) and no predicated inbound direct `bl` calls.
//! The body has one predicated `blne`, to [`cxx_string_copy_ctor`]. It walks
//! `[first, last)` in target-width string words, COW-constructing each word
//! into `output` only when the output cursor is non-null, then returns the
//! advanced output cursor. `owner` is passed by both callers but never read.
//!
//! Deliberate deviation: host tests substitute a word-copy observation seam
//! for the target COW constructor; non-test builds call it directly.

#[cfg(test)]
use core::ptr;

use crate::cxx::string::cxx_string_copy_ctor;

#[cfg(not(test))]
unsafe fn copy_string_word(destination: *mut u8, source: *const u8) {
    cxx_string_copy_ctor(destination.cast(), source.cast());
}

#[cfg(test)]
unsafe fn copy_string_word(destination: *mut u8, source: *const u8) {
    test_copy_string_word(destination, source);
}

/// COW-copies target-layout string words from `[first, last)` to `output`.
///
/// # Safety
///
/// `first..last` must delimit a forward-reachable range of readable target
/// string words. A non-null `output` must provide uninitialized writable words
/// for that range; each source word must be valid for `cxx_string_copy_ctor`.
/// The retail loop copies forward, so overlapping ranges are not moved.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_uninitialized_copy(
    mut first: *const u8,
    last: *const u8,
    mut output: *mut u8,
    _owner: *mut u8,
) -> *mut u8 {
    while first != last {
        if !output.is_null() {
            copy_string_word(output, first);
        }
        first = first.wrapping_add(4);
        output = output.wrapping_add(4);
    }
    output
}

#[cfg(test)]
static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
#[cfg(test)]
static mut CALLS: [(usize, usize); 8] = [(0, 0); 8];
#[cfg(test)]
static mut CALL_COUNT: usize = 0;

#[cfg(test)]
unsafe fn test_copy_string_word(destination: *mut u8, source: *const u8) {
    CALLS[CALL_COUNT] = (destination as usize, source as usize);
    CALL_COUNT += 1;
    ptr::write_unaligned(destination.cast::<u32>(), ptr::read_unaligned(source.cast::<u32>()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn copies_each_word_in_order_and_returns_output_end() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::CXX_STRING_UNINITIALIZED_COPY, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/cxx_string_uninitialized_copy"));
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let source = slab.add(0x100);
            let output = slab.add(0x200);
            for word in 0..3 {
                ptr::write_unaligned(source.add(word * 4).cast::<u32>(), (word + 1) as u32);
            }
            CALL_COUNT = 0;
            let returned = cxx_string_uninitialized_copy(source, source.add(12), output, ptr::null_mut());
            assert_eq!(returned, output.add(12));
            assert_eq!(CALL_COUNT, 3);
            for word in 0..3 {
                assert_eq!(ptr::read_unaligned(output.add(word * 4).cast::<u32>()), (word + 1) as u32);
                assert_eq!(CALLS[word], (output.add(word * 4) as usize, source.add(word * 4) as usize));
            }
        }
    }

    #[test]
    fn empty_range_returns_output_without_copying() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            CALL_COUNT = 0;
            let output = 0x4000usize as *mut u8;
            assert_eq!(cxx_string_uninitialized_copy(core::ptr::null(), core::ptr::null(), output, ptr::null_mut()), output);
            assert_eq!(CALL_COUNT, 0);
        }
    }

    #[test]
    fn null_output_skips_source_reads_and_advances() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            CALL_COUNT = 0;
            let first = 0x1000usize as *const u8;
            assert_eq!(cxx_string_uninitialized_copy(first, first.wrapping_add(4), ptr::null_mut(), ptr::null_mut()), 4usize as *mut u8);
            assert_eq!(CALL_COUNT, 0);
        }
    }
}
