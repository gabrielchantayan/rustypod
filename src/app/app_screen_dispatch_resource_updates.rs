//! Screen resource-update dispatch sequence.
//!
//! Original: `FUN_08219db4` @ `0x08219db4`, 156 bytes through the next
//! function at `0x08219e50`: 132 code bytes and six literal words.
//! Whole-image raw A32 decoding verifies one inbound BL (0x0821967c) and
//! one BLNE (0x082194a4). Outgoing: five plain BLs to app_screen_get,
//! zero predicated BLs, four BLXs and a final BX through vtable +0x58.
//!
//! Obtain the screen separately for each resource 0x7804, 0x7806, 0x7821,
//! 0x7843, 0x7842; dispatch (screen, 0x564d6178, resource), reloading its
//! vtable each time. Neither the opaque category nor virtual method is
//! assigned an invented identity. The input r0 is ignored.
//!
//! Deliberate deviations: typed repr(C) pointers widen on hosts; a host-only
//! getter seam permits changing singleton identities during dispatch. Expose
//! the final r0 word as u32 despite Ghidra's void signature. The reused
//! singleton port retains its documented NOT-HOOK-READY constructor caveat.

use super::singletons::app_screen_get;

pub type ScreenResourceDispatch = unsafe extern "C" fn(*mut ScreenResourceObject, u32, u32) -> u32;

#[repr(C)]
pub struct ScreenResourceVtable {
    pub preceding_slots: [usize; 0x58 / 4],
    pub dispatch: ScreenResourceDispatch,
}

#[repr(C)]
pub struct ScreenResourceObject {
    pub vtable: *const ScreenResourceVtable,
}

#[cfg(not(target_os = "none"))]
pub static mut APP_SCREEN_RESOURCE_GET: unsafe extern "C" fn() -> *mut u8 = app_screen_get;

/// Dispatch five resource updates, returning the final virtual result.
///
/// # Safety
/// Each singleton lookup must produce a live object with a callable +0x58
/// vtable slot. Dispatch may replace the singleton or vtable, but subsequent
/// lookups must remain valid. There are no NULL checks in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn app_screen_dispatch_resource_updates() -> u32 {
    let mut result = 0;
    for resource in [0x7804, 0x7806, 0x7821, 0x7843, 0x7842] {
        #[cfg(target_os = "none")]
        let screen = unsafe { app_screen_get() }.cast::<ScreenResourceObject>();
        #[cfg(not(target_os = "none"))]
        let screen = unsafe { (core::ptr::addr_of!(APP_SCREEN_RESOURCE_GET).read_volatile())() }
            .cast::<ScreenResourceObject>();
        let dispatch = unsafe { (*(*screen).vtable).dispatch };
        result = unsafe { dispatch(screen, 0x564d_6178, resource) };
    }
    result
}

#[cfg(target_os = "none")]
const _: () = assert!(core::mem::offset_of!(ScreenResourceVtable, dispatch) == 0x58);

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of, null_mut};

    #[repr(C)]
    struct Fixture {
        object: ScreenResourceObject,
        next: *mut Fixture,
        replacement: *const ScreenResourceVtable,
        state: u32,
    }

    static mut CURRENT: *mut Fixture = null_mut();
    unsafe extern "C" fn get() -> *mut u8 { unsafe { CURRENT.cast() } }

    unsafe extern "C" fn update(object: *mut ScreenResourceObject, category: u32, resource: u32) -> u32 {
        unsafe {
            let fixture = object.cast::<Fixture>();
            (*fixture).state = (*fixture).state.rotate_left(5) ^ category ^ resource;
            (*object).vtable = (*fixture).replacement;
            CURRENT = (*fixture).next;
            (*fixture).state
        }
    }
    unsafe extern "C" fn replacement(object: *mut ScreenResourceObject, category: u32, resource: u32) -> u32 {
        unsafe { update(object, category, resource).wrapping_add(17) }
    }

    struct Restore(unsafe extern "C" fn() -> *mut u8);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { APP_SCREEN_RESOURCE_GET = self.0; CURRENT = null_mut(); }
        }
    }

    #[test]
    fn observes_singleton_and_vtable_changes_and_final_return() {
        let original = ScreenResourceVtable { preceding_slots: [0; 22], dispatch: update };
        let changed = ScreenResourceVtable { preceding_slots: [0; 22], dispatch: replacement };
        unsafe {
            let _restore = Restore(addr_of!(APP_SCREEN_RESOURCE_GET).read());
            APP_SCREEN_RESOURCE_GET = get;
            for seed in [0, 1, 0x8000_0000, u32::MAX] {
                for switch_singleton in [false, true] {
                    let mut first = Fixture { object: ScreenResourceObject { vtable: &original }, next: null_mut(), replacement: &changed, state: seed };
                    let mut second = Fixture { object: ScreenResourceObject { vtable: &original }, next: &mut first, replacement: &changed, state: !seed };
                    first.next = if switch_singleton { &mut second } else { &mut first };
                    CURRENT = &mut first;
                    let mut expected = [seed, !seed];
                    for (index, resource) in [0x7804, 0x7806, 0x7821, 0x7843, 0x7842].into_iter().enumerate() {
                        let slot = if switch_singleton { index % 2 } else { 0 };
                        expected[slot] = expected[slot].rotate_left(5) ^ 0x564d_6178 ^ resource;
                    }
                    assert_eq!(app_screen_dispatch_resource_updates(), expected[0].wrapping_add(17));
                    assert_eq!((first.state, second.state), (expected[0], expected[1]));
                    assert!(CURRENT == if switch_singleton { &mut second } else { &mut first });
                }
            }
        }
    }
}
