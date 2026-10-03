//! Explicit activation and deactivation of a view's interaction mode.

use super::view_base::ViewBase;
use super::view_interaction_mode::view_set_interaction_mode;
use super::view_interaction_sync::ViewInteractionVtable;

/// view_set_interaction_active — original `FUN_0826d5a4` @ `0x0826d5a4`.
///
/// True size: 104 bytes; next function begins at 0x0826d60c. Raw ARM word
/// decoding finds two plain BL callers (0x0815786c, 0x0815791c), zero
/// predicated BL callers. Contains two plain BL instructions to the ported
/// view_set_interaction_mode and an indirect tail BX through vtable +0xc8.
/// A nonzero request changes mode 0x400 to 0x200 and notifies with 1; zero
/// changes mode 0x200 to 0x400 and notifies with 0. All other modes return
/// untouched. Surrounding flags survive; the callback sees the new mode.
/// Deviations: host vtable entries use native pointer width, as in the
/// existing interaction synchronization port; the target layout is unchanged.
///
/// # Safety
/// `view` must reference a writable ViewBase. A transition requires a valid
/// vtable with a callable interaction_changed slot at target offset +0xc8.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn view_set_interaction_active(view: *mut ViewBase, request: u32) {
    unsafe {
        let active = u32::from(request != 0);
        let (required_mode, new_mode) = if active != 0 { (0x400, 0x200) } else { (0x200, 0x400) };
        if (*view).flags & 0x600 != required_mode { return; }
        view_set_interaction_mode(view, new_mode);
        let vtable = (*view).vtable as usize as *const ViewInteractionVtable;
        ((*vtable).interaction_changed)(view, active);
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
    fn activation_transitions_and_callback_mutations() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::VIEW_INTERACTION_ACTIVE, 4096,
        ) else { return; };
        unsafe {
            let view = slab.cast::<ViewBase>();
            let table = slab.add(0x200).cast::<ViewInteractionVtable>();
            table.write(ViewInteractionVtable { preceding_slots: [0; 50], interaction_changed: changed });
            for mode in [0, 0x200, 0x400, 0x600] {
                for request in [0, 1, 2, 0x8000_0000, u32::MAX] {
                    let surrounding = 0xa5a5_99ff & !0x600;
                    (*view).flags = surrounding | mode;
                    let transition = (request == 0 && mode == 0x200) || (request != 0 && mode == 0x400);
                    // Inert paths must not even dereference the vtable.
                    (*view).vtable = if transition { table as usize as u32 } else { 0 };
                    CALLS.store(0, Ordering::Relaxed);
                    view_set_interaction_active(view, request);
                    assert_eq!(CALLS.load(Ordering::Relaxed), usize::from(transition));
                    if transition {
                        let active = u32::from(request != 0);
                        let expected = surrounding | if active != 0 { 0x200 } else { 0x400 };
                        assert_eq!(OBSERVED_VIEW.load(Ordering::Relaxed), view as usize);
                        assert_eq!(OBSERVED_ACTIVE.load(Ordering::Relaxed), active as usize);
                        assert_eq!(OBSERVED_FLAGS.load(Ordering::Relaxed), expected as usize);
                        assert_eq!((*view).flags, expected ^ 0x8000_0000);
                        view_set_interaction_active(view, request);
                        assert_eq!(CALLS.load(Ordering::Relaxed), 1);
                        assert_eq!((*view).flags, expected ^ 0x8000_0000);
                    } else {
                        assert_eq!((*view).flags, surrounding | mode);
                    }
                }
            }
        }
    }
}
