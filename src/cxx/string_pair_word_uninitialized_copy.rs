//! cxx_string_pair_word_uninitialized_copy — retailOS `FUN_083e8d2c` @
//! 0x083e8d2c (80 bytes; 0x083e8d2c..0x083e8d7c).
//!
//! Raw ARM has three inbound plain `bl` call sites and no predicated inbound
//! calls; its body calls [`cxx_string_copy_ctor`] twice, both unconditionally.
//! It uninitialized-copies the half-open range of 12-byte records containing
//! two COW strings followed by an opaque word. Each iteration checks its
//! current output cursor before reading source or constructing strings.
//! There are no deliberate deviations.

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

/// # Safety
///
/// `first..last` must delimit readable target-layout 12-byte records. If
/// `output` is non-null, it must provide uninitialized writable records for
/// the same range; each leading word must be valid for `cxx_string_copy_ctor`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_pair_word_uninitialized_copy(
    mut first: *const u8,
    last: *const u8,
    mut output: *mut u8,
) -> *mut u8 {
    while first != last {
        if !output.is_null() {
            copy_string_word(output, first);
            copy_string_word(output.add(4), first.add(4));
            output.add(8).cast::<u32>().write(first.add(8).cast::<u32>().read());
        }
        first = first.wrapping_add(12);
        output = output.wrapping_add(12);
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
    fn copies_two_target_layout_records_and_returns_end() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::CXX_STRING_PAIR_WORD_UNINITIALIZED_COPY, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/string_pair_word_uninitialized_copy"));
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let source = slab.add(0x100);
            let output = slab.add(0x200);
            for record in 0..2 {
                for word in 0..3 {
                    ptr::write_unaligned(
                        source.add(record * 12 + word * 4).cast::<u32>(),
                        (record * 3 + word + 1) as u32,
                    );
                }
            }
            CALL_COUNT = 0;
            let returned = cxx_string_pair_word_uninitialized_copy(source, source.add(24), output);
            assert_eq!(returned, output.add(24));
            assert_eq!(CALL_COUNT, 4);
            for record in 0..2 {
                for word in 0..3 {
                    assert_eq!(
                        ptr::read_unaligned(output.add(record * 12 + word * 4).cast::<u32>()),
                        (record * 3 + word + 1) as u32,
                    );
                }
                assert_eq!(CALLS[record * 2], (output.add(record * 12) as usize, source.add(record * 12) as usize));
                assert_eq!(CALLS[record * 2 + 1], (output.add(record * 12 + 4) as usize, source.add(record * 12 + 4) as usize));
            }
        }
    }

    #[test]
    fn null_output_skips_the_single_record_without_reading_source() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            CALL_COUNT = 0;
            let first = 0x1000usize as *const u8;
            let returned = cxx_string_pair_word_uninitialized_copy(first, first.wrapping_add(12), ptr::null_mut());
            assert_eq!(returned, 12usize as *mut u8);
            assert_eq!(CALL_COUNT, 0);
        }
    }
}
