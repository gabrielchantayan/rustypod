//! `scoped_global_guard_destroy` — original: `FUN_08155b6c` @ `0x08155b6c`
//! (64 bytes; 6 verified direct `bl` call sites, all unconditional).
//!
//! Raw ARM extent is exactly 64 bytes (`0x08155b6c..0x08155ba8`): 60 bytes
//! of instructions followed by the `0x08986aa0` vtable literal. The distinct
//! sibling starts at `0x08155bac`. The destructor first restores that vtable,
//! then reads its optional 4-byte allocation. A non-NULL allocation holds one
//! word supplied to the unmatched global guard-release entry at `0x0820c268`;
//! it releases that guard, tag-2-deletes the allocation through the already
//! ported `operator_delete` @ `0x082aad24`, and returns `this`. The final ARM
//! transfer is `b 0x0820c334`; raw bytes show that target is only `bx lr`, so
//! it preserves `this` in r0 and has no other effect.
//!
//! All six inbound calls are plain `bl` at `0x0813c504`, `0x0813c768`,
//! `0x08168894`, `0x08168958`, `0x08168a1c`, and `0x08168a7c`; there are no
//! predicated direct calls or inbound tail branches. The guard-release target
//! is a real function entry, but its product identity is not established, so
//! this module names it only for its observed acquire/release role.
//!
//! Deliberate deviation: Rust makes an ordinary call and return rather than
//! the final tail branch to the verified-empty `0x0820c334`; the observable
//! result is the same returned `this` pointer.

use crate::heap::veneers::operator_delete;

/// The vtable literal restored by the retail destructor.
const SCOPED_GLOBAL_GUARD_VTABLE: u32 = 0x0898_6aa0;

/// Target-width storage used by the stack-owned guard object.
///
/// Both fields are u32 because retailOS stores pointers in 32-bit words. Host
/// fixtures therefore map the object below 4 GiB rather than using host-width
/// pointer fields.
#[repr(C)]
pub struct ScopedGlobalGuard {
    vtable: u32,
    allocation: u32,
}

type GlobalGuardRelease = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn release_global_guard(payload: *mut u8) {
    let release: GlobalGuardRelease = unsafe { core::mem::transmute(0x0820_c268usize) };
    unsafe { release(payload) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn default_global_guard_release(_payload: *mut u8) {}

/// Host replacement for retailOS's unported global guard-release function.
///
/// The target address is a genuine function entry, but its identity is not
/// recovered; the host seam only models the observed argument and call order.
#[cfg(not(target_os = "none"))]
static mut HOST_GLOBAL_GUARD_RELEASE: GlobalGuardRelease = default_global_guard_release;

#[cfg(not(target_os = "none"))]
unsafe fn release_global_guard(payload: *mut u8) {
    let release = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(HOST_GLOBAL_GUARD_RELEASE)) };
    unsafe { release(payload) };
}

/// Destroys the stack-owned scoped global guard and returns `this`.
///
/// `this` must point to the two target-width words above. If `allocation` is
/// nonzero, it must point to a readable 4-byte payload accepted by the retail
/// guard release and the tag-2 allocator.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.scoped_global_guard_destroy")]
#[inline(never)]
pub unsafe extern "C" fn scoped_global_guard_destroy(
    this: *mut ScopedGlobalGuard,
) -> *mut ScopedGlobalGuard {
    unsafe {
        (*this).vtable = SCOPED_GLOBAL_GUARD_VTABLE;
        let allocation = (*this).allocation as usize as *mut u32;
        if !allocation.is_null() {
            release_global_guard(allocation.read() as usize as *mut u8);
            operator_delete(allocation.cast());
        }
    }
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    const ALLOCATION_OFFSET: usize = 0x100;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SCOPED_GLOBAL_GUARD_DESTROY, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut RELEASE_CALLS: usize = 0;
    static mut RELEASE_ARGUMENT: *mut u8 = ptr::null_mut();
    static mut FREE_CALLS_AT_RELEASE: usize = 0;

    unsafe extern "C" fn record_global_guard_release(payload: *mut u8) {
        unsafe {
            RELEASE_CALLS += 1;
            RELEASE_ARGUMENT = payload;
            FREE_CALLS_AT_RELEASE = free_log().0;
        }
    }

    struct ReleaseReset;

    impl Drop for ReleaseReset {
        fn drop(&mut self) {
            unsafe {
                HOST_GLOBAL_GUARD_RELEASE = default_global_guard_release;
            }
        }
    }

    fn fixture() -> Option<(*mut ScopedGlobalGuard, *mut u32)> {
        let base = (*FIXTURE)? as *mut u8;
        unsafe {
            ptr::write_bytes(base, 0, FIXTURE_LEN);
        }
        Some((base.cast(), unsafe { base.add(ALLOCATION_OFFSET).cast() }))
    }

    #[test]
    fn null_allocation_only_restores_the_vtable() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _reset = ReleaseReset;
        let Some((guard, _allocation)) = fixture() else {
            assert!(note_missing_u32_fixture("util/scoped_global_guard_destroy"));
            return;
        };
        unsafe {
            (*guard).vtable = 0xdead_beef;
            (*guard).allocation = 0;
            RELEASE_CALLS = 0;
            HOST_GLOBAL_GUARD_RELEASE = record_global_guard_release;
        }

        let result = unsafe { scoped_global_guard_destroy(guard) };

        assert_eq!(result, guard);
        assert_eq!(unsafe { (*guard).vtable }, SCOPED_GLOBAL_GUARD_VTABLE);
        assert_eq!(unsafe { RELEASE_CALLS }, 0);
    }

    #[test]
    fn releases_payload_before_deleting_nonnull_allocation() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _reset = ReleaseReset;
        let _heap = mock_heap();
        let Some((guard, allocation)) = fixture() else {
            assert!(note_missing_u32_fixture("util/scoped_global_guard_destroy"));
            return;
        };
        let payload = 0x1234_5678usize as *mut u8;
        unsafe {
            allocation.write(payload as usize as u32);
            (*guard).vtable = 0;
            (*guard).allocation = allocation as usize as u32;
            RELEASE_CALLS = 0;
            RELEASE_ARGUMENT = ptr::null_mut();
            FREE_CALLS_AT_RELEASE = usize::MAX;
            HOST_GLOBAL_GUARD_RELEASE = record_global_guard_release;
        }

        let result = unsafe { scoped_global_guard_destroy(guard) };

        assert_eq!(result, guard);
        assert_eq!(unsafe { (*guard).vtable }, SCOPED_GLOBAL_GUARD_VTABLE);
        assert_eq!(unsafe { RELEASE_CALLS }, 1);
        assert_eq!(unsafe { RELEASE_ARGUMENT }, payload);
        assert_eq!(unsafe { FREE_CALLS_AT_RELEASE }, 0, "release precedes operator delete");
        let (free_calls, freed, tag) = free_log();
        assert_eq!(free_calls, 1);
        assert_eq!(freed, allocation.cast());
        assert_eq!(tag, 2);
    }
}
