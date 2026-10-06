//! Guarded disk-mode resource dispatch — FUN_081594cc @ 0x081594cc.
//! True extent: 24 bytes through 0x081594e4 (20 code bytes and one literal).
//! Whole-image A32 decoding: two incoming plain BLs (0x08112c2c,
//! 0x081143c0), no incoming predicated BLs, and no outgoing BLs of either kind.
//! Load singleton 0x089cc79c; return zero if NULL, otherwise tail-enter
//! 0x081594b0, which dispatches vtable +0x58 with wildcard 0x2a2a2a2a and
//! resource 0x8ca8. Neither the resource's meaning nor the virtual callee's
//! identity is established. Preserve the final r0 result despite Ghidra's void.
//! Deliberate deviations: Rust calls the virtual slot instead of sharing the
//! preceding ARM tail body. Host pointers widen in the reused repr(C) layout;
//! a host singleton replaces the fixed RAM address. No target behavior changes.

use super::app_screen_dispatch_resource_updates::ScreenResourceObject;

#[cfg(not(target_os = "none"))]
pub static mut DISK_MODE_RESOURCE_RECEIVER: *mut ScreenResourceObject = core::ptr::null_mut();

/// Dispatch resource 0x8ca8 only when the disk-mode receiver exists.
///
/// # Safety
/// A non-null singleton must be live with a callable vtable slot +0x58.
/// Host singleton installation and calls must be serialized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn disk_mode_resource_8ca8_dispatch() -> u32 {
    #[cfg(target_os = "none")]
    let receiver = (0x089c_c79cusize as *const *mut ScreenResourceObject).read_volatile();
    #[cfg(not(target_os = "none"))]
    let receiver = core::ptr::addr_of!(DISK_MODE_RESOURCE_RECEIVER).read_volatile();
    if receiver.is_null() {
        return 0;
    }
    ((*(*receiver).vtable).dispatch)(receiver, 0x2a2a_2a2a, 0x8ca8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::app_screen_dispatch_resource_updates::ScreenResourceVtable;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[repr(C)]
    struct Fixture {
        object: ScreenResourceObject,
        state: u32,
    }

    unsafe extern "C" fn dispatch(receiver: *mut ScreenResourceObject, category: u32, resource: u32) -> u32 {
        assert_eq!(category, 0x2a2a_2a2a);
        assert_eq!(resource, 0x8ca8);
        let fixture = receiver.cast::<Fixture>();
        (*fixture).state = (*fixture).state.wrapping_add(1);
        DISK_MODE_RESOURCE_RECEIVER = core::ptr::null_mut();
        (*fixture).state
    }

    struct Restore(*mut ScreenResourceObject);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { DISK_MODE_RESOURCE_RECEIVER = self.0; }
        }
    }

    #[test]
    fn absent_receiver_and_dispatch_removal_preserve_result() {
        let _lock = LOCK.lock();
        unsafe {
            let _restore = Restore(DISK_MODE_RESOURCE_RECEIVER);
            DISK_MODE_RESOURCE_RECEIVER = core::ptr::null_mut();
            assert_eq!(disk_mode_resource_8ca8_dispatch(), 0);
            let vtable = ScreenResourceVtable { preceding_slots: [0; 22], dispatch };
            for state in [0, 0x7fff_ffff, u32::MAX] {
                let mut fixture = Fixture { object: ScreenResourceObject { vtable: &vtable }, state };
                DISK_MODE_RESOURCE_RECEIVER = &mut fixture.object;
                assert_eq!(disk_mode_resource_8ca8_dispatch(), state.wrapping_add(1));
                assert_eq!(fixture.state, state.wrapping_add(1));
                assert!(DISK_MODE_RESOURCE_RECEIVER.is_null());
                assert_eq!(disk_mode_resource_8ca8_dispatch(), 0);
                assert_eq!(fixture.state, state.wrapping_add(1));
            }
        }
    }
}
