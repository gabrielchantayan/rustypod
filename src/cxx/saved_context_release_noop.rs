//! `saved_context_release_noop` — original `FUN_080276c0` @ 0x080276c0.
//!
//! True extent: [0x080276c0, 0x080276c4), 4 bytes: e12fff1e (`bx lr`).
//! The next entry is independently called at 0x083438a8 and 0x08348188.
//! Complete aligned raw A32 decoding verifies two incoming plain BLs
//! (0x082faa9c, 0x08312d7c), zero predicated BLs, zero outgoing calls,
//! and no aligned DATA address references. This is not a veneer.
//!
//! Algorithm: return the saved context unchanged without accessing memory.
//! Callers load it from sp+0x14c and sp+0x148 respectively, then discard r0.
//! Concrete context type and destructor identity are unrecovered; there are
//! no callees or new seams. Deliberate deviation: expose preserved r0 rather
//! than Ghidra's void prototype. Naked target assembly retains the original
//! register-transparent body and prevents folding into other empty functions.

use core::ffi::c_void;

/// Accept any context address, including NULL, unaligned, or dangling values.
#[cfg(target_os = "none")]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn saved_context_release_noop(_context: *mut c_void) -> *mut c_void {
    core::arch::naked_asm!("bx lr");
}

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn saved_context_release_noop(context: *mut c_void) -> *mut c_void {
    context
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_null_unaligned_dangling_and_native_width_addresses() {
        for word in [0usize, 1, 3, 0x0800_0000, u32::MAX as usize, usize::MAX] {
            let context = word as *mut c_void;
            assert_eq!(unsafe { saved_context_release_noop(context) }, context);
        }
    }

    #[test]
    fn preserves_live_context_and_adjacent_storage() {
        let mut storage = [0xa5u8; 64];
        storage[17..47].fill(0x3c);
        let before = storage;
        for offset in [0, 1, 17, 47, 63] {
            let context = unsafe { storage.as_mut_ptr().add(offset) }.cast();
            assert_eq!(unsafe { saved_context_release_noop(context) }, context);
            assert_eq!(storage, before);
        }
    }
}
