//! Conditional lifecycle-mode transitions and notification.

use super::view_base::ViewBase;
use super::view_lifecycle_mode::view_set_lifecycle_mode;

/// Runtime vtable slot +0xbc; host fixtures use native-width slots.
#[repr(C)]
pub struct ViewLifecycleVtable {
    pub preceding_slots: [usize; 47],
    pub lifecycle_changed: unsafe extern "C" fn(*mut ViewBase, u32),
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xbc] = [0; core::mem::offset_of!(ViewLifecycleVtable, lifecycle_changed)];

/// view_sync_lifecycle_mode — original `FUN_0826daa8` @ `0x0826daa8`.
///
/// True size: 104 bytes, through the tail BX at 0x0826db0c; the next real
/// function starts at 0x0826db10. Raw ARM words verify two unconditional
/// BL callers and zero predicated BL callers. Contains two unconditional
/// BL instructions to view_set_lifecycle_mode and one indirect tail BX.
/// A nonzero request changes mode 0x4000 to 0x2000 and notifies with 1;
/// zero changes 0x2000 to 0x4000 and notifies with 0. Other modes return
/// untouched. Surrounding flags survive, and notification sees the new mode.
/// Deviations: host vtables use native-width slots; target layout is unchanged.
///
/// # Safety
/// `view` must reference a writable ViewBase. Transition paths require a
/// valid target-width vtable address with a callable slot +0xbc.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_sync_lifecycle_mode(view: *mut ViewBase, request: u32) {
    unsafe {
        let old_mode = (*view).flags & 0x6000;
        let notification;
        if request == 0 {
            if old_mode != 0x2000 { return; }
            view_set_lifecycle_mode(view, 0x4000);
            notification = 0;
        } else {
            if old_mode != 0x4000 { return; }
            view_set_lifecycle_mode(view, 0x2000);
            notification = 1;
        }
        let vtable = (*view).vtable as usize as *const ViewLifecycleVtable;
        ((*vtable).lifecycle_changed)(view, notification);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static OBSERVED_VIEW: AtomicUsize = AtomicUsize::new(0);
    static OBSERVED_ACTIVE: AtomicUsize = AtomicUsize::new(0);
    static OBSERVED_FLAGS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn changed(view: *mut ViewBase, active: u32) {
        CALLS.fetch_add(1, Ordering::Relaxed);
        OBSERVED_VIEW.store(view as usize, Ordering::Relaxed);
        OBSERVED_ACTIVE.store(active as usize, Ordering::Relaxed);
        OBSERVED_FLAGS.store(unsafe { (*view).flags } as usize, Ordering::Relaxed);
        unsafe { (*view).flags ^= 0x8000_0000; }
    }

    #[test]
    fn transitions_notify_once_after_update_and_other_modes_do_not_dispatch() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::VIEW_LIFECYCLE_SYNC, 4096,
        ) else { return; };
        unsafe {
            let view = slab.cast::<ViewBase>();
            let table = slab.add(0x200).cast::<ViewLifecycleVtable>();
            table.write(ViewLifecycleVtable { preceding_slots: [0; 47], lifecycle_changed: changed });
            for surrounding in [0, 0xa5a5_9fff, 0xffff_9fff] {
                for mode in [0, 0x2000, 0x4000, 0x6000] {
                    for request in [0, 1, 2, u32::MAX] {
                        let notify = (request == 0 && mode == 0x2000)
                            || (request != 0 && mode == 0x4000);
                        // Null vtables are valid on paths that must not dispatch.
                        (*view).vtable = if notify { table as usize as u32 } else { 0 };
                        (*view).flags = surrounding | mode;
                        CALLS.store(0, Ordering::Relaxed);
                        view_sync_lifecycle_mode(view, request);
                        let expected = surrounding | if notify {
                            if request == 0 { 0x4000 } else { 0x2000 }
                        } else { mode };
                        assert_eq!(CALLS.load(Ordering::Relaxed), usize::from(notify));
                        if notify {
                            assert_eq!(OBSERVED_VIEW.load(Ordering::Relaxed), view as usize);
                            assert_eq!(OBSERVED_ACTIVE.load(Ordering::Relaxed), usize::from(request != 0));
                            assert_eq!(OBSERVED_FLAGS.load(Ordering::Relaxed), expected as usize);
                        }
                        assert_eq!((*view).flags, expected ^ if notify { 0x8000_0000 } else { 0 });
                    }
                }
            }
        }
    }
}
