//! Surface-plane owner release — original: `FUN_0814492c` @ `0x0814492c`
//! (104 bytes; exact extent confirmed by the next `push` at `0x08144994`).
//!
//! Verified call count: six inbound direct `bl` sites (all unconditional,
//! `0x0811a1d8`, `0x08145cbc`, `0x08145e28`, `0x08146010`, `0x08146244`,
//! and `0x0814638c`); the body makes six direct unconditional `bl` calls
//! (three plane lookups and three frees) plus one virtual `blx` through the
//! surface vtable's release slot.
//!
//! The owner holds a surface at +0x20. A NULL slot returns immediately.
//! Otherwise it releases the surface's plane 0, 2, and 3 addresses through
//! the default heap with tag `0x35`, even when a lookup returns NULL; invokes
//! the surface vtable's +0x04 release method; and finally clears the slot.
//!
//! Deliberate deviation: the target's target-width surface and vtable words
//! use native-width pointers on 64-bit hosts. The named `#[repr(C)]` field
//! remains at +0x20, while the shared `SurfaceVtable` preserves the target's
//! two-slot dispatch on device and permits a real host callback in tests.

use crate::drivers::display_layer::{surface_plane_address, SurfaceVtable};
use crate::heap::veneers::free_wrapper;

/// Heap caller tag loaded before each of the three plane frees.
const SURFACE_PLANE_FREE_TAG: usize = 0x35;

/// The accessed prefix of the owner object. `surface` is at +0x20 on the
/// target; its native-width host representation has no following known field
/// to overlap.
#[repr(C)]
pub struct SurfacePlaneOwner {
    _prefix: [u8; 0x20],
    pub surface: *mut u8,
}

/// Releases the owner-held surface's three allocated plane addresses, invokes
/// its vtable release method, and clears `owner.surface`.
#[inline(never)]
#[cfg_attr(target_os = "none", link_section = ".text.surface_release_owned_planes")]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn surface_release_owned_planes(owner: *mut SurfacePlaneOwner) {
    let surface = unsafe { core::ptr::addr_of!((*owner).surface).read_volatile() };
    if surface.is_null() {
        return;
    }

    unsafe {
        free_wrapper(surface_plane_address(surface, 0) as *mut u8, SURFACE_PLANE_FREE_TAG);
        free_wrapper(surface_plane_address(surface, 2) as *mut u8, SURFACE_PLANE_FREE_TAG);
        free_wrapper(surface_plane_address(surface, 3) as *mut u8, SURFACE_PLANE_FREE_TAG);

        let vtable = (surface as *const *const SurfaceVtable).read_volatile();
        ((*vtable).release)(surface);
        core::ptr::addr_of_mut!((*owner).surface).write_volatile(core::ptr::null_mut());
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const SURFACE_FORMAT: usize = 0x08;
    const SURFACE_PLANE_A: usize = 0x24;
    const SURFACE_PLANE_B: usize = 0x28;
    const SURFACE_PLANE_C: usize = 0x2c;
    const PLANE_A_OFFSET: usize = 0x100;
    const PLANE_B_OFFSET: usize = 0x200;
    const PLANE_C_OFFSET: usize = 0x300;
    const OWNER_OFFSET: usize = 0x800;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SURFACE_PLANE_OWNER_RELEASE, FIXTURE_LEN).map(|p| p as usize)
    });
    static RELEASE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RELEASED_SURFACE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn retain_unused(_: *mut u8) {}

    unsafe extern "C" fn record_release(surface: *mut u8) {
        RELEASED_SURFACE.store(surface as usize, Ordering::Relaxed);
        RELEASE_CALLS.fetch_add(1, Ordering::Relaxed);
    }

    static TEST_VTABLE: SurfaceVtable = SurfaceVtable {
        retain: retain_unused,
        release: record_release,
    };

    unsafe fn fixture(format: u8) -> Option<(*mut SurfacePlaneOwner, *mut u8)> {
        let Some(base) = *FIXTURE else {
            return None;
        };
        let base = base as *mut u8;
        unsafe { core::ptr::write_bytes(base, 0, FIXTURE_LEN) };
        let surface = base;
        unsafe {
            (surface as *mut *const SurfaceVtable).write(core::ptr::addr_of!(TEST_VTABLE));
            surface.add(SURFACE_FORMAT).write(format);
            surface.add(SURFACE_PLANE_A).cast::<u32>().write((base.add(PLANE_A_OFFSET)) as usize as u32);
            surface.add(SURFACE_PLANE_B).cast::<u32>().write((base.add(PLANE_B_OFFSET)) as usize as u32);
            surface.add(SURFACE_PLANE_C).cast::<u32>().write((base.add(PLANE_C_OFFSET)) as usize as u32);
            let owner = base.add(OWNER_OFFSET).cast::<SurfacePlaneOwner>();
            core::ptr::addr_of_mut!((*owner).surface).write(surface);
            Some((owner, surface))
        }
    }

    #[test]
    fn null_surface_returns_without_heap_or_vtable_work() {
        let mut owner = SurfacePlaneOwner {
            _prefix: [0; 0x20],
            surface: core::ptr::null_mut(),
        };
        RELEASE_CALLS.store(0, Ordering::Relaxed);
        unsafe { surface_release_owned_planes(&mut owner) };
        assert!(owner.surface.is_null());
        assert_eq!(RELEASE_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn planar_surface_releases_three_planes_then_vtable_and_clears_slot() {
        let _heap_guard = mock_heap();
        let Some((owner, surface)) = (unsafe { fixture(0) }) else {
            assert!(note_missing_u32_fixture("drivers::surface_plane_owner"));
            return;
        };
        RELEASE_CALLS.store(0, Ordering::Relaxed);
        RELEASED_SURFACE.store(0, Ordering::Relaxed);

        unsafe { surface_release_owned_planes(owner) };

        let (free_calls, last_pointer, last_tag) = free_log();
        assert_eq!(free_calls, 3, "one unconditional free per requested plane");
        assert_eq!(last_pointer, unsafe { surface.add(PLANE_C_OFFSET) });
        assert_eq!(last_tag, SURFACE_PLANE_FREE_TAG);
        assert_eq!(RELEASE_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(RELEASED_SURFACE.load(Ordering::Relaxed), surface as usize);
        assert!(unsafe { (*owner).surface }.is_null());
    }

    #[test]
    fn missing_planar_components_still_reach_the_unguarded_free_path() {
        let _heap_guard = mock_heap();
        let Some((owner, surface)) = (unsafe { fixture(1) }) else {
            assert!(note_missing_u32_fixture("drivers::surface_plane_owner"));
            return;
        };
        RELEASE_CALLS.store(0, Ordering::Relaxed);

        unsafe { surface_release_owned_planes(owner) };

        let (free_calls, last_pointer, last_tag) = free_log();
        assert_eq!(free_calls, 3);
        assert!(last_pointer.is_null(), "format 1 has no plane index 3");
        assert_eq!(last_tag, SURFACE_PLANE_FREE_TAG);
        assert_eq!(RELEASE_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(RELEASED_SURFACE.load(Ordering::Relaxed), surface as usize);
        assert!(unsafe { (*owner).surface }.is_null());
    }
}
