//! Synchronization of a view's interaction mode with its linked view.

use super::view_base::ViewBase;
use super::view_interaction_mode::view_set_interaction_mode;

/// Runtime vtable slot +0xc8, with host-width entries in host fixtures.
#[repr(C)]
pub struct ViewInteractionVtable {
    pub preceding_slots: [usize; 50],
    pub interaction_changed: unsafe extern "C" fn(*mut ViewBase, u32),
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xc8] = [0; core::mem::offset_of!(ViewInteractionVtable, interaction_changed)];

/// view_sync_interaction_mode — original `FUN_0826eca4` @ `0x0826eca4`.
///
/// True size: 160 bytes; next function starts at 0x0826ed44. Raw word decoding
/// finds two plain BL callers (0x081585d8, 0x08158688), zero predicated BL
/// callers. Contains two BL instructions to view_set_interaction_mode, one
/// tail B to that setter, and one indirect tail BX through vtable +0xc8.
/// On zero request, sets mode 0x600 and notifies with zero only if the old
/// mode was 0x200. On nonzero request, only mode 0x600 is considered: a
/// linked view at +0x34 in mode 0x200 permits mode 0x200 and notification 1;
/// otherwise sets mode 0x400 without notification. Other flag bits survive.
/// Deviations: host vtables use native-width slots; target layout is unchanged.
///
/// # Safety
/// `view` must reference a writable ViewBase. When read, its target-width
/// linked-view word at +0x34 must be null or reference a readable ViewBase.
/// Notification paths require a valid vtable and slot +0xc8 callback.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_sync_interaction_mode(view: *mut ViewBase, request: u32) {
    unsafe {
        let old_mode = (*view).flags & 0x600;
        let notification;
        if request == 0 {
            view_set_interaction_mode(view, 0x600);
            if old_mode != 0x200 { return; }
            notification = 0;
        } else {
            if old_mode != 0x600 { return; }
            let linked = view.cast::<u32>().add(13).read() as usize as *const ViewBase;
            if linked.is_null() || ((*linked).flags & 0x600) != 0x200 {
                view_set_interaction_mode(view, 0x400);
                return;
            }
            view_set_interaction_mode(view, 0x200);
            notification = 1;
        }
        let vtable = (*view).vtable as usize as *const ViewInteractionVtable;
        ((*vtable).interaction_changed)(view, notification);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static OBSERVED_VIEW: AtomicUsize = AtomicUsize::new(0);
    static OBSERVED_ACTIVE: AtomicUsize = AtomicUsize::new(0);
    static OBSERVED_FLAGS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn changed(view: *mut ViewBase, active: u32) {
        OBSERVED_VIEW.store(view as usize, Ordering::Relaxed);
        OBSERVED_ACTIVE.store(active as usize, Ordering::Relaxed);
        OBSERVED_FLAGS.store(unsafe { (*view).flags } as usize, Ordering::Relaxed);
        // Callback mutations must survive the dispatch.
        unsafe { (*view).flags ^= 0x8000_0000; }
    }

    #[test]
    fn transitions_preserve_flags_and_notify_after_the_setter() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::VIEW_INTERACTION_SYNC, 4096,
        ) else { return; };
        unsafe {
            let view = slab.cast::<ViewBase>();
            let linked = slab.add(0x100).cast::<ViewBase>();
            let table = slab.add(0x200).cast::<ViewInteractionVtable>();
            table.write(ViewInteractionVtable { preceding_slots: [0; 50], interaction_changed: changed });
            (*view).vtable = table as usize as u32;
            for mode in [0, 0x200, 0x400, 0x600] {
                for linked_mode in [None, Some(0), Some(0x200), Some(0x400), Some(0x600)] {
                    for request in [0, 1, 2, u32::MAX] {
                        let surrounding = 0xa5a5_99ff & !0x600;
                        (*view).flags = surrounding | mode;
                        view.cast::<u32>().add(13).write(if let Some(parent_mode) = linked_mode {
                            (*linked).flags = surrounding | parent_mode;
                            linked as usize as u32
                        } else { 0 });
                        OBSERVED_VIEW.store(0, Ordering::Relaxed);
                        let (expected_mode, notify) = if request == 0 {
                            (0x600, if mode == 0x200 { Some(0) } else { None })
                        } else if mode != 0x600 {
                            (mode, None)
                        } else if linked_mode == Some(0x200) {
                            (0x200, Some(1))
                        } else {
                            (0x400, None)
                        };
                        view_sync_interaction_mode(view, request);
                        let expected_flags = surrounding | expected_mode;
                        let observed = match OBSERVED_VIEW.load(Ordering::Relaxed) {
                            0 => None,
                            address => Some((address, OBSERVED_ACTIVE.load(Ordering::Relaxed) as u32,
                                OBSERVED_FLAGS.load(Ordering::Relaxed) as u32)),
                        };
                        assert_eq!(observed, notify.map(|n| (view as usize, n, expected_flags)));
                        assert_eq!((*view).flags, expected_flags ^ if notify.is_some() { 0x8000_0000 } else { 0 });
                        if let Some(parent_mode) = linked_mode {
                            assert_eq!((*linked).flags, surrounding | parent_mode);
                        }
                    }
                }
            }
        }
    }
}
