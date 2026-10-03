//! Default construction of the deque-related layout used by polygon processing.

use super::three_word_clear_eleventh::three_word_clear_eleventh;
use crate::runtime::cpp_array_construct::cpp_array_construct;

/// deque_layout_construct — original: `FUN_0824cc94` @ `0x0824cc94`.
/// True extent: 56 bytes (`0x0824cc94..0x0824cccc`): 52 bytes of code and
/// the callback literal at `0x0824ccc8`; the next real function is the copy
/// constructor at `0x0824cccc`. Whole-image aligned A32 decoding verifies
/// two inbound plain BL calls (0x08240b78, 0x08240b80), four outbound plain
/// BL instructions, and no predicated BL forms in either direction.
///
/// Initializes two four-word fixed-point records at +0 and +0x10 to
/// (0, 0, 0, 0x10000), clears three words at +0x30, and constructs three
/// 16-byte records at +0x3c through the existing array adapter. Returns the
/// adapter's actual result minus 0x3c, not necessarily the incoming pointer.
/// Words +0x20..+0x2c and +0x6c onward are untouched by the direct stores.
///
/// Deliberate deviations: inline the deterministic stores of 0x0824c758
/// rather than port a second function; use volatile stores to retain order.
/// Preserve the raw callback word 0x0823d814 without assigning it a callee
/// identity: raw decoding shows mid-function instructions, not an ABI entry.
/// Use u32 word offsets so host pointer width cannot alter the target layout.
///
/// # Safety
/// `storage` must be aligned, writable storage for the 37-word layout. The
/// array helper must satisfy the retail constructor contract for its three
/// elements and returned pointer. No NULL guard exists in the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn deque_layout_construct(storage: *mut u32) -> *mut u32 {
    for offset in [0, 4] {
        let record = storage.add(offset);
        record.add(2).write_volatile(0);
        record.add(1).write_volatile(0);
        record.write_volatile(0);
        record.add(3).write_volatile(0x10000);
    }
    let cleared = three_word_clear_eleventh(storage.add(12));
    cpp_array_construct(cleared.add(3), 0x0823_d814, 0x10, 3).wrapping_sub(15)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::pair_header::{PairHeaderElementArrayOps, PAIR_HEADER_ELEMENT_ARRAY_OPS};

    struct Restore(PairHeaderElementArrayOps);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { PAIR_HEADER_ELEMENT_ARRAY_OPS = self.0; }
        }
    }

    unsafe extern "C" fn initialized_array(
        array: *mut u32, _count: u32, _size: u32, _header: u32,
        _argument: u32, _initializer: u32, _context: u32,
        _allocator: u32, _allocator_context: u32, _flags: u32, _zero: u32,
    ) -> *mut u32 {
        // Exercise the full constructor with a non-identity helper result.
        for index in 0..12 {
            array.add(index).write(0x1234_0000 + index as u32);
        }
        array.add(4)
    }

    #[test]
    fn initializes_fields_preserves_gaps_and_returns_adjusted_helper_result() {
        let _lock = match crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock() {
            Ok(guard) => guard,
            Err(error) => panic!("shared array constructor test lock poisoned: {error}"),
        };
        let _restore = Restore(unsafe { PAIR_HEADER_ELEMENT_ARRAY_OPS });
        unsafe { PAIR_HEADER_ELEMENT_ARRAY_OPS = PairHeaderElementArrayOps { reset: initialized_array }; }
        for fill in [0, 0xffff_ffff, 0xa5a5_5a5a] {
            let mut words = [fill; 39];
            let storage = unsafe { words.as_mut_ptr().add(1) };
            let result = unsafe { deque_layout_construct(storage) };
            assert_eq!(result, unsafe { storage.add(4) });
            assert_eq!(&words[1..9], &[0, 0, 0, 0x10000, 0, 0, 0, 0x10000]);
            assert_eq!(&words[9..13], &[fill; 4]);
            assert_eq!(&words[13..16], &[0; 3]);
            for index in 0..12 {
                assert_eq!(words[16 + index], 0x1234_0000 + index as u32);
            }
            assert_eq!(words[0], fill);
            assert_eq!(&words[28..], &[fill; 11]);
        }
    }
}
