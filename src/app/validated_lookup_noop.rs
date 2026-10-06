//! `validated_lookup_noop` — original: `FUN_0815b104` @ 0x0815b104.
//!
//! True extent: 4 bytes, [0x0815b104, 0x0815b108). Raw word e12fff1e
//! is `bx lr`; the preceding function ends with e8bd8010 at 0x0815b100,
//! and the next function begins with e59f0004 at 0x0815b108. Not a veneer.
//! Whole-image aligned A32 decoding verifies two incoming plain BLs
//! (0x081f62e8, 0x081f6420), zero predicated BLs, and zero outgoing calls.
//! No aligned image word contains this address as a data/vtable reference.
//!
//! Both callers pass the receiver at object+0x94 and mode 0 or 1 after
//! 0x0815b118 reports a successful lookup; they ignore the return and then
//! increment object+0x9e. No class identity or setter behavior is inferred.
//! Algorithm: ignore mode, touch no memory, preserve the receiver in r0.
//! Deliberate deviations: none; the explicit return models raw r0 preservation
//! despite Ghidra's void signature. A distinct text section prevents folding
//! with other empty exports. No callee seams are required.

use core::ffi::c_void;

/// Returns the receiver unchanged without dereferencing it, for any mode.
/// Null, unaligned, and dangling receiver values are accepted.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.validated_lookup_noop")]
#[inline(never)]
pub unsafe extern "C" fn validated_lookup_noop(receiver: *mut c_void, _mode: u32) -> *mut c_void {
    receiver
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_non_dereferenceable_receivers_for_all_mode_boundaries() {
        for word in [0usize, 1, 0x0800_0001, 0x8000_0000, u32::MAX as usize, usize::MAX] {
            let receiver = word as *mut c_void;
            for mode in [0, 1, 2, 0x8000_0000, u32::MAX] {
                assert_eq!(unsafe { validated_lookup_noop(receiver, mode) }, receiver);
            }
        }
    }

    #[test]
    fn leaves_receiver_storage_unchanged() {
        let mut storage = [0xa5u8; 256];
        let before = storage;
        for mode in [0, 1, u32::MAX] {
            let receiver = storage.as_mut_ptr().cast();
            assert_eq!(unsafe { validated_lookup_noop(receiver, mode) }, receiver);
            assert_eq!(storage, before);
        }
    }
}
