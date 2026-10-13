//! `obfuscated_context_noop` — `FUN_080276ac` @ **0x080276ac**, 4 bytes.
//!
//! Raw word `0xe12fff1e` is `bx lr`; true extent is [0x080276ac, 0x080276b0).
//! The next word is an independent `bx lr` entry with four distinct callers.
//! Whole-image aligned A32 decoding finds two plain inbound BLs at 0x08343cf0
//! and 0x08348354, zero predicated inbound BLs, zero outgoing calls, and no
//! aligned DATA words referencing this address.
//!
//! The obfuscated state-machine callers at 0x0834358c and 0x08348038 load
//! r0 from sp+0x134 and sp+0x130 respectively; neither consumes the result.
//! Algorithm: return immediately without accessing memory, preserving r0.
//! The concrete context type and destructor identity are not established.
//! Deliberate deviations: expose the preserved word as a pointer return despite
//! Ghidra's void prototype. A dedicated text section prevents identical-body
//! folding; LLVM may introduce a balanced frame instead of the stock `bx lr`.

use core::ffi::c_void;

/// Preserve an opaque context word without dereferencing it.
/// NULL, unaligned, and dangling values are accepted.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.obfuscated_context_noop")]
#[inline(never)]
pub unsafe extern "C" fn obfuscated_context_noop(context: *mut c_void) -> *mut c_void {
    context
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_arbitrary_context_words_without_dereferencing() {
        for word in [0usize, 1, 3, 0x0800_0000, 0x8000_0001, 0xffff_ffff, usize::MAX] {
            let context = word as *mut c_void;
            assert_eq!(unsafe { obfuscated_context_noop(context) }, context);
        }
    }

    #[test]
    fn leaves_live_storage_and_adjacent_sentinels_unchanged() {
        let mut storage = [0xa5u8; 64];
        for (index, byte) in storage[8..56].iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(37);
        }
        let before = storage;
        for offset in [8, 9, 11, 55] {
            let context = unsafe { storage.as_mut_ptr().add(offset) }.cast::<c_void>();
            assert_eq!(unsafe { obfuscated_context_noop(context) }, context);
            assert_eq!(storage, before);
        }
    }
}
