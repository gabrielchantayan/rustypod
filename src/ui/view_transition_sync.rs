//! Synchronization of a view's shown state with its parent.

use super::invalidate::ui_element_invalidate_region;
use super::shown_state::ui_element_is_shown;
use super::view_base::ViewBase;
use super::view_transition_mode::view_set_transition_mode;

/// Runtime vtable slot +0xa8; host fixtures use native-width entries.
#[repr(C)]
pub struct ViewTransitionVtable {
    pub preceding_slots: [usize; 42],
    pub shown_changed: unsafe extern "C" fn(*mut ViewBase, u32),
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xa8] = [0; core::mem::offset_of!(ViewTransitionVtable, shown_changed)];

/// view_sync_transition_mode — original `FUN_0826ea9c` @ `0x0826ea9c`.
///
/// True size: 192 bytes, ending before the next prologue at 0x0826eb5c.
/// Raw decoding finds two plain BL callers (0x08158508, 0x081585b8), zero
/// predicated BL callers; the body contains five plain BLs, zero predicated
/// BLs, one tail B to the mode setter, and an indirect tail BX at +0xa8.
/// Zero request invalidates the old bounds before setting mode 0x1800,
/// notifying with zero only when the old mode was 0x800. Nonzero request
/// only acts on mode 0x1800: a shown parent permits mode 0x800, bounds
/// invalidation, then notification 1; otherwise sets mode 0x1000 silently.
/// Unrelated flag bits and callback mutations survive.
/// Deviations: host vtable entries have native width; object pointer words
/// retain target width. Rust does not require the stock tail-call lowering.
///
/// # Safety
/// `view` must be a writable ViewBase. Its +0x34 parent word must be null or
/// a readable UI element on activation. Invalidation requires the existing
/// invalidation API's object/parent/render-context layout. Notification
/// paths require a valid vtable and callback at slot +0xa8.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_sync_transition_mode(view: *mut ViewBase, request: u32) {
    unsafe {
        let old_mode = (*view).flags & 0x1800;
        let notification;
        let bounds = core::ptr::addr_of!((*view).bounds).cast();
        if request == 0 {
            if old_mode == 0x1800 { return; }
            ui_element_invalidate_region(view.cast(), bounds);
            view_set_transition_mode(view, 0x1800);
            if old_mode != 0x800 { return; }
            notification = 0;
        } else {
            if old_mode != 0x1800 { return; }
            let parent = view.cast::<u32>().add(13).read() as usize as *const u8;
            if parent.is_null() || ui_element_is_shown(parent) == 0 {
                view_set_transition_mode(view, 0x1000);
                return;
            }
            view_set_transition_mode(view, 0x800);
            ui_element_invalidate_region(view.cast(), bounds);
            notification = 1;
        }
        let vtable = (*view).vtable as usize as *const ViewTransitionVtable;
        ((*vtable).shown_changed)(view, notification);
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
        unsafe { (*view).flags ^= 0x8000_0000; }
    }

    #[test]
    fn all_modes_parent_states_and_requests_preserve_notification_semantics() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::VIEW_TRANSITION_SYNC, 4096,
        ) else { return; };
        unsafe {
            let view = slab.cast::<ViewBase>();
            let parent = slab.add(0x100).cast::<ViewBase>();
            let table = slab.add(0x300).cast::<ViewTransitionVtable>();
            table.write(ViewTransitionVtable { preceding_slots: [0; 42], shown_changed: changed });
            (*view).vtable = table as usize as u32;
            // Real invalidation exits at its per-element suppression byte:
            // no global seams are replaced and no host-width parent is read.
            slab.add(0xa0).write(1);
            for mode in [0, 0x800, 0x1000, 0x1800] {
                for parent_mode in [None, Some(0), Some(0x800), Some(0x1000), Some(0x1800)] {
                    for request in [0, 1, 2, u32::MAX] {
                        let surrounding = 0xa5a5_e7ff & !0x1800;
                        (*view).flags = surrounding | mode;
                        view.cast::<u32>().add(13).write(if let Some(flags) = parent_mode {
                            (*parent).flags = surrounding | flags;
                            parent as usize as u32
                        } else { 0 });
                        OBSERVED_VIEW.store(0, Ordering::Relaxed);
                        let (expected_mode, notify) = if request == 0 {
                            (0x1800, if mode == 0x800 { Some(0) } else { None })
                        } else if mode != 0x1800 {
                            (mode, None)
                        } else if parent_mode == Some(0x800) {
                            (0x800, Some(1))
                        } else {
                            (0x1000, None)
                        };
                        view_sync_transition_mode(view, request);
                        let expected_flags = surrounding | expected_mode;
                        let observed = match OBSERVED_VIEW.load(Ordering::Relaxed) {
                            0 => None,
                            address => Some((address, OBSERVED_ACTIVE.load(Ordering::Relaxed) as u32,
                                OBSERVED_FLAGS.load(Ordering::Relaxed) as u32)),
                        };
                        assert_eq!(observed, notify.map(|n| (view as usize, n, expected_flags)));
                        assert_eq!((*view).flags, expected_flags ^ if notify.is_some() { 0x8000_0000 } else { 0 });
                        if let Some(flags) = parent_mode {
                            assert_eq!((*parent).flags, surrounding | flags);
                        }
                    }
                }
            }
        }
    }
}
