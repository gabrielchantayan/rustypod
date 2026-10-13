//! `context_cleanup_noop` — `FUN_080276a0` @ `0x080276a0`, 4 bytes.
//!
//! True extent: `0x080276a0..0x080276a4`; the next distinct empty function
//! starts at `0x080276a4`. Raw word `0xe12fff1e` decodes to `bx lr`.
//! Whole-image aligned A32 decoding verifies two inbound plain BLs
//! (`0x082f8f20`, `0x08332b70`), zero predicated BLs, zero outbound calls,
//! and no aligned DATA references. Both callers load a context word into r0.
//!
//! Algorithm: return immediately without accessing memory, preserving r0.
//! Deliberate deviations: none. The explicit return exposes the preserved
//! context word even though Ghidra reports void. A distinct text section
//! retains this BL target rather than folding it with another empty leaf.
//! The ARM body is naked to avoid a frame-pointer prologue and stack writes.

use core::ffi::c_void;

/// Perform the stock register-preserving cleanup without accessing memory.
#[cfg(all(target_os = "none", target_arch = "arm"))]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.context_cleanup_noop")]
pub unsafe extern "C" fn context_cleanup_noop(context: *mut c_void) -> *mut c_void {
    core::arch::naked_asm!("bx lr");
}

/// Host equivalent of the register-preserving target leaf.
#[cfg(not(all(target_os = "none", target_arch = "arm")))]
/// Perform the empty context cleanup, accepting any context word unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.context_cleanup_noop")]
#[inline(never)]
pub unsafe extern "C" fn context_cleanup_noop(context: *mut c_void) -> *mut c_void {
    context
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_null_unaligned_and_unmapped_context_words() {
        for word in [0usize, 1, 3, 0x0800_0000, 0x8000_0001, 0xffff_ffff, usize::MAX] {
            let context = word as *mut c_void;
            assert_eq!(unsafe { context_cleanup_noop(context) }, context);
        }
    }

    #[test]
    fn leaves_context_storage_and_surrounding_bytes_unchanged() {
        let mut storage = [0xa5u8; 256];
        for (index, byte) in storage[4..252].iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17);
        }
        let before = storage;
        let context = unsafe { storage.as_mut_ptr().add(4) }.cast::<c_void>();
        assert_eq!(unsafe { context_cleanup_noop(context) }, context);
        assert_eq!(storage, before);
    }
}
