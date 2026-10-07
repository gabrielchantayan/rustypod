//! `parse_context_destroy` — `FUN_08162aec` @ **0x08162aec**, 4 bytes.
//!
//! Raw word `0xe12fff1e` is `bx lr`. The two-word zeroing constructor
//! at 0x08162adc returns at 0x08162ae8; the next real function starts at
//! 0x08162af0 (`mov r0, #0; bx lr`). Whole-image aligned ARM decoding finds
//! two inbound plain BLs (0x08119ebc, 0x081b1f10), zero predicated BLs,
//! zero internal BLs, and no aligned DATA words containing this address.
//!
//! Both callers construct an eight-byte stack context, pass it to the
//! buffer-processing wrapper at 0x08162ac0, and destroy it on scope exit.
//! Algorithm: return immediately without reading or writing the context,
//! preserving its pointer in r0. No specific parser format is assumed.
//! Deliberate deviations: none. A distinct text section prevents folding
//! with other empty destructors and preserves this independently hookable target.

use core::ffi::c_void;

/// Destroy the parsing temporary without accessing memory.
///
/// NULL, unaligned, and dangling object words are accepted unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.parse_context_destroy")]
#[inline(never)]
pub unsafe extern "C" fn parse_context_destroy(context: *mut c_void) -> *mut c_void {
    context
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_null_unaligned_and_dangling_context_words() {
        for word in [0usize, 1, 3, 0x0800_0000, 0x8000_0001, 0xffff_ffff, usize::MAX] {
            let context = word as *mut c_void;
            assert_eq!(unsafe { parse_context_destroy(context) }, context);
        }
    }

    #[test]
    fn preserves_context_and_surrounding_canaries() {
        let mut storage = [0xdead_beefu32, 0, 0, 0xa5a5_a5a5];
        for words in [[0, 0], [1, u32::MAX], [0x1234_5678, 0x8765_4321]] {
            storage[1..3].copy_from_slice(&words);
            let before = storage;
            let context = unsafe { storage.as_mut_ptr().add(1) }.cast::<c_void>();
            assert_eq!(unsafe { parse_context_destroy(context) }, context);
            assert_eq!(storage, before);
        }
    }
}
