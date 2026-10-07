//! `fat_format_context_destroy` — `FUN_0814cbb0` @ **0x0814cbb0**, 4 bytes.
//!
//! Raw A32 word `0xe12fff1e` is `bx lr`; the next real function starts
//! at 0x0814cbb4 with `stmdb sp!, {r4,r5,r6,lr}`. Whole-image aligned
//! decoding verifies two inbound plain BLs (0x080d6c58, 0x080d6cf8), zero
//! predicated BLs, zero outgoing BLs, and no aligned DATA references.
//!
//! Caller 0x080d6ba4 constructs an eight-byte context through 0x0814cb9c
//! (vtable word and borrowed storage object), uses it at 0x0814c8ac to
//! prepare FAT32 boot/partition data and write a sector, then destroys it
//! on both result paths. Both calls discard r0. Algorithm: return without
//! accessing memory, preserving the incoming context pointer in r0.
//! Deliberate deviations: none. Naked ARM assembly retains the original
//! register-transparent single instruction; the host model returns its pointer.

use core::ffi::c_void;

/// Destroy the borrowed formatting context without accessing its storage.
/// NULL, unaligned, and dangling pointer words are accepted unchanged.
#[cfg(target_os = "none")]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fat_format_context_destroy(_context: *mut c_void) -> *mut c_void {
    core::arch::naked_asm!("bx lr");
}

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn fat_format_context_destroy(context: *mut c_void) -> *mut c_void {
    context
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_null_unaligned_and_invalid_pointer_words() {
        for word in [0usize, 1, 3, 0x0800_0000, 0x8000_0001, 0xffff_ffff, usize::MAX] {
            let context = word as *mut c_void;
            assert_eq!(unsafe { fat_format_context_destroy(context) }, context);
        }
    }

    #[test]
    fn leaves_borrowed_context_and_adjacent_canaries_unchanged() {
        for words in [[0, 0], [0x0898_67dc, 0x0800_0000], [u32::MAX, 1]] {
            let mut storage = [0xdead_beefu32, words[0], words[1], 0xa5a5_a5a5];
            let before = storage;
            let context = unsafe { storage.as_mut_ptr().add(1) }.cast::<c_void>();
            assert_eq!(unsafe { fat_format_context_destroy(context) }, context);
            assert_eq!(storage, before);
        }
    }
}
