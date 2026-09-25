//! cxx_string_pair_entry_range_assign — retailOS `FUN_083e9cbc` @ 0x083e9cbc.
//!
//! **76 bytes**, true extent `0x083e9cbc..0x083e9d08`, bounded by the next
//! independently linked range helper at 0x083e9d08. Raw whole-image A32
//! decoding finds two inbound plain `bl` call sites and no predicated forms.
//! The routine walks a half-open range of 12-byte target-layout entries,
//! assigning COW string words at offsets +0x00 and +0x04 through
//! [`cxx_string_assign`], copying the unexamined word at +0x08, then returning
//! the advanced output cursor. There are no deliberate deviations.

#[cfg(not(test))]
use crate::cxx::string::cxx_string_assign;

#[cfg(not(test))]
unsafe fn assign_string_word(destination: *mut u8, source: *const u8) {
    cxx_string_assign(destination.cast(), source.cast());
}

#[cfg(test)]
unsafe fn assign_string_word(destination: *mut u8, source: *const u8) {
    test_assign_string_word(destination, source);
}

/// Assigns each 12-byte COW string-pair entry in `first..last` into `output`.
///
/// # Safety
///
/// `first..last` must delimit readable 12-byte target-layout entries. `output`
/// must provide writable entries for the same range; every COW string word must
/// be valid for `cxx_string_assign`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_pair_entry_range_assign(
    mut first: *const u8,
    last: *const u8,
    mut output: *mut u8,
) -> *mut u8 {
    while first != last {
        assign_string_word(output, first);
        assign_string_word(output.add(4), first.add(4));
        output.add(8).cast::<u32>().write(first.add(8).cast::<u32>().read());
        first = first.add(12);
        output = output.add(12);
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
unsafe fn test_assign_string_word(destination: *mut u8, source: *const u8) {
    CALLS[CALL_COUNT] = (destination as usize, source as usize);
    CALL_COUNT += 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn cxx_string_pair_entry_range_assigns_strings_copies_trailing_word_and_returns_end() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::CXX_STRING_PAIR_ENTRY_RANGE_ASSIGN, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/cxx_string_pair_entry_range_assign"));
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let source = slab.add(0x100);
            let output = slab.add(0x300);
            source.add(8).cast::<u32>().write(0x1122_3344);
            source.add(20).cast::<u32>().write(0x5566_7788);
            CALL_COUNT = 0;

            let returned = cxx_string_pair_entry_range_assign(source, source.add(24), output);

            assert_eq!(returned, output.add(24));
            assert_eq!(CALL_COUNT, 4);
            assert_eq!(CALLS[0], (output as usize, source as usize));
            assert_eq!(CALLS[1], (output.add(4) as usize, source.add(4) as usize));
            assert_eq!(CALLS[2], (output.add(12) as usize, source.add(12) as usize));
            assert_eq!(CALLS[3], (output.add(16) as usize, source.add(16) as usize));
            assert_eq!(output.add(8).cast::<u32>().read(), 0x1122_3344);
            assert_eq!(output.add(20).cast::<u32>().read(), 0x5566_7788);
        }
    }

    #[test]
    fn cxx_string_pair_entry_range_assign_empty_preserves_output_without_calls() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            CALL_COUNT = 0;
            let output = 0x2000usize as *mut u8;
            assert_eq!(cxx_string_pair_entry_range_assign(core::ptr::null(), core::ptr::null(), output), output);
            assert_eq!(CALL_COUNT, 0);
        }
    }
}
