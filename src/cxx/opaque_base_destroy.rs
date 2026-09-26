//! Destruction of the opaque base embedded in vtable-bearing records.
//!
//! ## Original: `FUN_083dadd4` @ `0x083dadd4`
//!
//! Raw A32 establishes a 52-byte instruction extent,
//! `0x083dadd4..0x083dae04`; `0x089a87dc` at `0x083dae08` is its literal and
//! the next independently linked function begins at `0x083dae0c`. It has no
//! plain `bl` instructions and one predicated `blne` to
//! `cxx_allocator_deallocate` @ `0x083d7ff8`; its two incoming call sites are
//! plain `bl` instructions. The function installs its destruction vtable,
//! conditionally frees the pointer/count pair at words two and three when bit
//! zero of word four is set, then tail-branches to the embedded shared-array
//! handle release at word eleven and returns the original base address.
//!
//! Deliberate deviation: the tail branch is an ordinary call, and the
//! identified-but-unported shared-array release remains an exact-address ARM
//! seam with a replaceable host seam.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

use crate::heap::veneers::cxx_allocator_deallocate;

const RETAIL_SHARED_ARRAY_HANDLE_RELEASE: usize = 0x082a_8ba0;
const DESTRUCTION_VTABLE: u32 = 0x089a_87dc;
const ALLOCATION_POINTER_WORD: usize = 2;
const ALLOCATION_COUNT_WORD: usize = 3;
const ALLOCATION_FLAG_WORD: usize = 4;
const SHARED_ARRAY_HANDLE_WORD: usize = 11;

pub type OpaqueSharedArrayHandleRelease = unsafe extern "C" fn(*mut u32) -> *mut u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_shared_array_handle(handle: *mut u32) -> *mut u32 {
    core::mem::transmute::<usize, OpaqueSharedArrayHandleRelease>(RETAIL_SHARED_ARRAY_HANDLE_RELEASE)(handle)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_shared_array_handle_release(handle: *mut u32) -> *mut u32 { handle }

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_SHARED_ARRAY_HANDLE_RELEASE: OpaqueSharedArrayHandleRelease = missing_shared_array_handle_release;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn release_shared_array_handle(handle: *mut u32) -> *mut u32 {
    core::ptr::read_volatile(addr_of!(OPAQUE_SHARED_ARRAY_HANDLE_RELEASE))(handle)
}

/// Destroys the base at `base` and returns that same address. `base` must
/// provide words zero through eleven; when allocation bit zero is set, words
/// two and three are the pointer and count accepted by the allocator veneer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_base_destroy(base: *mut u32) -> *mut u32 {
    base.write(DESTRUCTION_VTABLE);
    if base.add(ALLOCATION_FLAG_WORD).read() & 1 != 0 {
        cxx_allocator_deallocate(
            base.cast::<u8>(),
            base.add(ALLOCATION_POINTER_WORD).read() as *mut u8,
            base.add(ALLOCATION_COUNT_WORD).read() as usize,
        );
    }
    release_shared_array_handle(base.add(SHARED_ARRAY_HANDLE_WORD)).sub(SHARED_ARRAY_HANDLE_WORD)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    static mut RELEASE_ARGUMENT: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn release(handle: *mut u32) -> *mut u32 {
        RELEASE_ARGUMENT = handle;
        handle
    }

    struct Reset { _lock: MutexGuard<'static, ()>, release: OpaqueSharedArrayHandleRelease }
    impl Drop for Reset {
        fn drop(&mut self) { unsafe { OPAQUE_SHARED_ARRAY_HANDLE_RELEASE = self.release; } }
    }
    fn reset() -> Reset {
        let lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe {
            let reset = Reset { _lock: lock, release: OPAQUE_SHARED_ARRAY_HANDLE_RELEASE };
            OPAQUE_SHARED_ARRAY_HANDLE_RELEASE = release;
            RELEASE_ARGUMENT = core::ptr::null_mut();
            reset
        }
    }

    #[test]
    fn destroys_base_and_releases_embedded_handle_without_allocation() {
        let _reset = reset();
        let Some(slab) = try_map_u32_slab(hints::OPAQUE_BASE_DESTROY, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/opaque_base_destroy")); return;
        };
        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let base = slab.cast::<u32>().add(16);
            base.add(ALLOCATION_POINTER_WORD).write(0);
            base.add(ALLOCATION_COUNT_WORD).write(usize::MAX as u32);
            base.add(ALLOCATION_FLAG_WORD).write(0);
            assert_eq!(opaque_base_destroy(base), base);
            assert_eq!(base.read(), DESTRUCTION_VTABLE);
            assert_eq!(RELEASE_ARGUMENT, base.add(SHARED_ARRAY_HANDLE_WORD));
        }
    }

    #[test]
    fn allocation_flag_accepts_null_allocation() {
        let _reset = reset();
        let Some(slab) = try_map_u32_slab(hints::OPAQUE_BASE_DESTROY_NULL_ALLOCATION, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/opaque_base_destroy null allocation")); return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let base = slab.cast::<u32>().add(16);
            base.add(ALLOCATION_FLAG_WORD).write(1);
            assert_eq!(opaque_base_destroy(base), base);
            assert_eq!(RELEASE_ARGUMENT, base.add(SHARED_ARRAY_HANDLE_WORD));
        }
    }
}
