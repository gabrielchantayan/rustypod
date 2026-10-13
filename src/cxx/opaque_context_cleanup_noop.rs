//! `opaque_context_cleanup_noop` — original: `FUN_080276c4` @ 0x080276c4.
//!
//! True extent: 4 bytes, 0x080276c4..0x080276c8. Raw word 0xe12fff1e
//! is `bx lr`; the next entry starts with `cmp r0,#0` and has independent
//! callers. Whole-image aligned ARM decoding finds two incoming plain BLs
//! at 0x083438a8 and 0x08348188, zero predicated BLs, and no aligned address
//! literals. Both callers pass a saved context value and discard the result.
//! This is not a veneer; concrete context type and destructor identity are
//! unrecovered. There are no callees or memory accesses.
//!
//! Algorithm: return the incoming context address unchanged in r0.
//! Deliberate deviation: expose the preserved r0 rather than Ghidra's void
//! signature. A dedicated section keeps the target distinct from identical
//! cleanup bodies; LLVM may add balanced frame-pointer stack traffic.

use core::ffi::c_void;

/// Leaves the context and its address unchanged, including NULL, dangling,
/// and unaligned addresses. No pointee validity is required.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_context_cleanup_noop")]
#[inline(never)]
pub unsafe extern "C" fn opaque_context_cleanup_noop(context: *mut c_void) -> *mut c_void {
    context
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_null_unaligned_and_dangling_addresses() {
        for address in [0usize, 1, 0x0800_0001, 0x0802_76c4, usize::MAX] {
            let context = address as *mut c_void;
            assert_eq!(unsafe { opaque_context_cleanup_noop(context) }, context);
        }
    }

    #[test]
    fn leaves_live_context_storage_unchanged() {
        let mut storage = [0xa5u8; 64];
        let before = storage;
        let context = storage.as_mut_ptr().cast();
        assert_eq!(unsafe { opaque_context_cleanup_noop(context) }, context);
        assert_eq!(storage, before);
    }
}
