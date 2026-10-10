//! Counted-path timestamp query — FUN_080b42e4 at 0x080b42e4.
//!
//! Raw extent: 52 bytes (0x080b42e4..0x080b4318), ending in pop {r4,pc}
//! before the next function's push. Two plain BLs, zero predicated BLs.
//! Clear a 72-byte aligned workspace, resolve the counted path through
//! 0x0805a8e4 with no optional result, and return the u32 at workspace +8
//! regardless of resolver status. Callers use it as a timestamp and apply
//! timezone adjustments in seconds.
//! Deliberate deviations: Rust initializes eighteen u32 words instead of
//! calling the IRAM zero-fill veneer; the existing replaceable resolver seam
//! emits an indirect BLX instead of the stock direct BL. No status filtering.
//! ARM match.py: 18 versus 13 instructions; LLVM uses __aeabi_memclr4
//! for the same 72-byte clear and BLX for the resolver. The final load
//! remains [sp,#8], with no branch or status check after resolution.

use crate::app::path_facade_resolve_relative::PATH_FACADE_RESOLVE_COUNTED_IMPL;

/// # Safety
/// `path` must be a valid counted path accepted by the stock resolver (u16
/// prefix followed by a NUL-terminated byte string). The resolver seam must
/// honor its ABI and not write beyond the 72-byte workspace.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_timestamp(path: *mut u8) -> u32 {
    let mut workspace = [0u32; 18];
    let resolver = core::ptr::read_volatile(core::ptr::addr_of!(PATH_FACADE_RESOLVE_COUNTED_IMPL));
    resolver(path, workspace.as_mut_ptr(), core::ptr::null_mut());
    workspace[2]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::path_facade_resolve_relative::PathFacadeResolveCountedImpl;

    unsafe extern "C" fn fail_before_timestamp(_: *mut u8, workspace: *mut u32, _: *mut u16) -> i32 {
        // A partial metadata result must not become the timestamp.
        workspace.add(1).write(u32::MAX);
        workspace.add(3).write(12345);
        -43
    }

    unsafe extern "C" fn populate_timestamp(path: *mut u8, workspace: *mut u32, _: *mut u16) -> i32 {
        workspace.add(2).write((path as *const u32).read());
        // Timestamp output, not status, is authoritative even on failure.
        -50
    }

    struct Restore(PathFacadeResolveCountedImpl);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { PATH_FACADE_RESOLVE_COUNTED_IMPL = self.0; } }
    }

    #[test]
    fn early_failure_returns_zero_not_status_or_adjacent_metadata() {
        let _lock = crate::testing::PATH_FACADE_RESOLVE_RELATIVE_TEST_LOCK.lock();
        unsafe {
            let _restore = Restore(PATH_FACADE_RESOLVE_COUNTED_IMPL);
            PATH_FACADE_RESOLVE_COUNTED_IMPL = fail_before_timestamp;
            let mut path = [0u32; 2];
            assert_eq!(path_timestamp(path.as_mut_ptr().cast()), 0);
        }
    }

    #[test]
    fn timestamp_preserves_all_bits_even_when_resolver_reports_failure() {
        let _lock = crate::testing::PATH_FACADE_RESOLVE_RELATIVE_TEST_LOCK.lock();
        unsafe {
            let _restore = Restore(PATH_FACADE_RESOLVE_COUNTED_IMPL);
            PATH_FACADE_RESOLVE_COUNTED_IMPL = populate_timestamp;
            for timestamp in [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
                let mut path = [timestamp, 0];
                assert_eq!(path_timestamp(path.as_mut_ptr().cast()), timestamp);
            }
        }
    }
}
