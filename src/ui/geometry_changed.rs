//! View-base geometry-change redraw propagation.
//!
//! `view_base_geometry_changed` — original: `FUN_0826db38` @
//! **0x0826db38**, 96 bytes. Raw bytes run from `push {r4,lr}` at
//! 0x0826db38 through `pop {r4,pc}` at 0x0826db94; the next function opens
//! at 0x0826db98. Whole-image ARM decoding finds five direct call sites:
//! two unconditional `bl` and three predicated `bl*` forms.
//!
//! It sets view flag 0x20, invalidates the view bounds, conditionally calls
//! parent vtable slot +0x128, then calls view vtable slot +0x5c and sets flag
//! 0x40 on that returned owner. The two virtual-slot identities remain
//! unresolved, so host tests use operations that preserve their observed ABI;
//! target builds dispatch through the retail target-word vtables.
//!
//! Deliberate deviation: host virtual dispatch cannot use 32-bit firmware
//! code pointers, so it uses replaceable operations. The ported invalidation
//! call remains direct on both targets.

use core::ptr;

use crate::ui::invalidate::ui_element_invalidate_region;
use crate::ui::view_base::ViewBase;

const FLAGS_OFFSET: usize = 0x48;
const PARENT_OFFSET: usize = 0x34;
const BOUNDS_OFFSET: usize = 0x80;
const SUPPRESS_NOTIFY_OFFSET: usize = 0xa0;

#[cfg(not(target_os = "none"))]
pub type GeometryChangedParentNotify = unsafe extern "C" fn(*mut u8);
#[cfg(not(target_os = "none"))]
pub type GeometryChangedOwner = unsafe extern "C" fn(*mut ViewBase) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_parent_notify(_parent: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_owner(_view: *mut ViewBase) -> *mut u8 { ptr::null_mut() }

/// Host substitutions for the two unresolved virtual calls in the retail body.
#[cfg(not(target_os = "none"))]
pub static mut GEOMETRY_CHANGED_PARENT_NOTIFY: GeometryChangedParentNotify = no_parent_notify;
#[cfg(not(target_os = "none"))]
pub static mut GEOMETRY_CHANGED_OWNER: GeometryChangedOwner = no_owner;

#[cfg(target_os = "none")]
unsafe fn notify_parent(parent: *mut u8) {
    let vtable = parent.cast::<u32>().read_volatile() as usize;
    let notify: unsafe extern "C" fn() = core::mem::transmute(
        (vtable as *const u32).add(0x128 / 4).read_volatile() as usize,
    );
    notify();
}

#[cfg(not(target_os = "none"))]
unsafe fn notify_parent(parent: *mut u8) {
    ptr::read_volatile(ptr::addr_of!(GEOMETRY_CHANGED_PARENT_NOTIFY))(parent);
}

#[cfg(target_os = "none")]
unsafe fn view_owner(view: *mut ViewBase) -> *mut u8 {
    let vtable = view.cast::<u32>().read_volatile() as usize;
    let owner: unsafe extern "C" fn(*mut ViewBase) -> *mut u8 = core::mem::transmute(
        (vtable as *const u32).add(0x5c / 4).read_volatile() as usize,
    );
    owner(view)
}

#[cfg(not(target_os = "none"))]
unsafe fn view_owner(view: *mut ViewBase) -> *mut u8 {
    ptr::read_volatile(ptr::addr_of!(GEOMETRY_CHANGED_OWNER))(view)
}

/// view_base_geometry_changed — original: `FUN_0826db38` @ 0x0826db38
/// (96 bytes; five direct call sites: two unconditional, three predicated).
///
/// # Safety
/// `view` must point to a writable ViewBase-sized object. Its bounds, flags,
/// parent linkage, and both virtual dispatch targets must be valid.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_base_geometry_changed(view: *mut ViewBase) {
    let view_bytes = view.cast::<u8>();
    view_bytes.add(FLAGS_OFFSET).cast::<u32>().write_volatile(
        view_bytes.add(FLAGS_OFFSET).cast::<u32>().read_volatile() | 0x20,
    );
    ui_element_invalidate_region(view_bytes, view_bytes.add(BOUNDS_OFFSET).cast());

    let parent = view_bytes.add(PARENT_OFFSET).cast::<u32>().read_volatile() as usize as *mut u8;
    if !parent.is_null() && view_bytes.add(SUPPRESS_NOTIFY_OFFSET).read_volatile() == 0 {
        notify_parent(parent);
    }
    let owner = view_owner(view);
    owner.add(FLAGS_OFFSET).cast::<u32>().write_volatile(
        owner.add(FLAGS_OFFSET).cast::<u32>().read_volatile() | 0x40,
    );
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::Mutex;

    const SLAB_LEN: usize = 0x1000;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut PARENT_CALLS: u32 = 0;
    static mut OWNER: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn record_parent(_parent: *mut u8) { PARENT_CALLS += 1; }
    unsafe extern "C" fn record_owner(_view: *mut ViewBase) -> *mut u8 { OWNER }

    #[test]
    fn marks_view_and_owner_and_gates_parent_notification() {
        let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(slab) = (unsafe { try_map_u32_slab(hints::VIEW_BASE_GEOMETRY_CHANGED, SLAB_LEN) }) else {
            note_missing_u32_fixture("view_base_geometry_changed");
            return;
        };
        unsafe {
            let view = slab.cast::<ViewBase>();
            let owner = slab.add(0x400);
            view.cast::<u8>().add(FLAGS_OFFSET).cast::<u32>().write(0x800);
            owner.add(FLAGS_OFFSET).cast::<u32>().write(1);
            OWNER = owner;
            GEOMETRY_CHANGED_PARENT_NOTIFY = record_parent;
            GEOMETRY_CHANGED_OWNER = record_owner;
            PARENT_CALLS = 0;
            view_base_geometry_changed(view);
            assert_eq!(view.cast::<u8>().add(FLAGS_OFFSET).cast::<u32>().read(), 0x820);
            assert_eq!(owner.add(FLAGS_OFFSET).cast::<u32>().read(), 0x41);
            assert_eq!(PARENT_CALLS, 0);
            view.cast::<u8>().add(PARENT_OFFSET).cast::<u32>().write((slab.add(0x800)) as usize as u32);
            view_base_geometry_changed(view);
            assert_eq!(PARENT_CALLS, 1);
            view.cast::<u8>().add(SUPPRESS_NOTIFY_OFFSET).write(1);
            view_base_geometry_changed(view);
            assert_eq!(PARENT_CALLS, 1);
            GEOMETRY_CHANGED_PARENT_NOTIFY = no_parent_notify;
            GEOMETRY_CHANGED_OWNER = no_owner;
        }
    }
}
