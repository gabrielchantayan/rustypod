//! cxx_string_range_assign — retailOS `FUN_083e9e00` @ 0x083e9e00 (56
//! bytes; 0x083e9e00..0x083e9e38).
//!
//! Raw ARM has two inbound plain `bl` call sites and no predicated inbound
//! calls. Its body has one unconditional `bl` per iteration, to
//! [`cxx_string_assign`]. It assigns each COW string in the target-layout
//! half-open source word range to the corresponding destination word, then
//! returns the advanced destination cursor. There are no deliberate deviations.

#[cfg(test)]
use core::ptr;

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

/// Assigns each target-layout COW string word in `first..last` into `output`.
///
/// # Safety
///
/// `first..last` must delimit readable, four-byte-aligned target-layout COW
/// string words. `output` must provide writable COW string words for the same
/// range; each source and destination word must be valid for `cxx_string_assign`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_range_assign(
    mut first: *const u8,
    last: *const u8,
    mut output: *mut u8,
) -> *mut u8 {
    while first != last {
        assign_string_word(output, first);
        first = first.add(4);
        output = output.add(4);
    }
    output
}

#[cfg(test)]
static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
#[cfg(test)]
static mut CALLS: [(usize, usize); 4] = [(0, 0); 4];
#[cfg(test)]
static mut CALL_COUNT: usize = 0;

#[cfg(test)]
unsafe fn test_assign_string_word(destination: *mut u8, source: *const u8) {
    CALLS[CALL_COUNT] = (destination as usize, source as usize);
    CALL_COUNT += 1;
    ptr::write_unaligned(destination.cast::<u32>(), ptr::read_unaligned(source.cast::<u32>()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn assigns_every_word_and_returns_end_cursor() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::CXX_STRING_RANGE_ASSIGN, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/cxx_string_range_assign"));
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
            let returned = cxx_string_range_assign(source, source.add(12), output);
            assert_eq!(returned, output.add(12));
            assert_eq!(CALL_COUNT, 3);
            for word in 0..3 {
                assert_eq!(ptr::read_unaligned(output.add(word * 4).cast::<u32>()), (word + 1) as u32);
                assert_eq!(CALLS[word], (output.add(word * 4) as usize, source.add(word * 4) as usize));
            }
        }
    }

    #[test]
    fn empty_range_returns_output_without_calling_assignment() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            CALL_COUNT = 0;
            let output = 0x2000usize as *mut u8;
            assert_eq!(cxx_string_range_assign(ptr::null(), ptr::null(), output), output);
            assert_eq!(CALL_COUNT, 0);
        }
    }
}
