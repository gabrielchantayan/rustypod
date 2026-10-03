//! `comparison_context_destroy` — `FUN_08267d84` @ **0x08267d84**, 4 bytes.
//!
//! Raw word `0xe12fff1e` is `bx lr`; the preceding constructor returns at
//! 0x08267d80 and the next real function starts at 0x08267d88 with
//! `stmdb sp!, {r4-r10, lr}`. Whole-image aligned ARM decoding verifies two
//! inbound plain BLs (0x08267b40, 0x08267b48), zero predicated BLs, zero
//! internal BLs, and no aligned DATA words containing this address.
//!
//! Both callers destroy the 20-byte comparison context constructed at
//! 0x08267d6c and queried at 0x08267cf8, on its failure and success paths.
//! Algorithm: return immediately, preserving the object word in r0 and all
//! object bytes. The caller does not consume r0, but the raw body preserves it.
//! Deliberate deviations: none. A distinct text section prevents identical
//! function folding with other empty destructors and retains this BL target.

use core::ffi::c_void;

/// Destroy the comparison temporary without accessing memory.
///
/// NULL, unaligned, and dangling object words are accepted unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.comparison_context_destroy")]
#[inline(never)]
pub unsafe extern "C" fn comparison_context_destroy(object: *mut c_void) -> *mut c_void {
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_null_unaligned_and_dangling_object_words() {
        for word in [0usize, 1, 3, 0x0800_0000, 0x8000_0001, 0xffff_ffff, usize::MAX] {
            let object = word as *mut c_void;
            assert_eq!(unsafe { comparison_context_destroy(object) }, object);
        }
    }

    #[test]
    fn preserves_all_twenty_context_bytes_and_surrounding_canaries() {
        let mut storage = [0xa5u8; 28];
        for (index, byte) in storage[4..24].iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17);
        }
        let before = storage;
        let object = unsafe { storage.as_mut_ptr().add(4) }.cast::<c_void>();
        assert_eq!(unsafe { comparison_context_destroy(object) }, object);
        assert_eq!(storage, before);
    }
}
