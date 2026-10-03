//! Direct activation and deactivation of a view's transition state.

use super::view_base::ViewBase;
use super::view_transition_mode::view_set_transition_mode;
use super::view_transition_sync::ViewTransitionVtable;

/// view_set_transition_active — original `FUN_0826caf8` @ `0x0826caf8`.
///
/// True size: 104 bytes, through the indirect tail BX at 0x0826cb5c;
/// the next function begins at 0x0826cb60. Raw ARM word decoding verifies
/// two plain inbound BLs (0x081574d8, 0x08157588), no predicated inbound
/// BLs, and two plain outbound BLs to view_set_transition_mode, no
/// predicated outbound BLs. Nonzero requests change mode 0x1000 to 0x800
/// and notify vtable +0xa8 with 1. Zero requests change mode 0x800 to
/// 0x1000 and notify with 0. All other modes are untouched, without
/// accessing the vtable. The mode update precedes notification; unrelated
/// flags and callback mutations survive.
/// Deviations: host vtable slots use native width; object words retain
/// target width. Rust does not require the stock indirect tail-call form.
///
/// # Safety
/// `view` must point to a writable ViewBase. A transitioning view must
/// contain a valid vtable word and a callable shown_changed slot at +0xa8.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_set_transition_active(view: *mut ViewBase, request: u32) {
    unsafe {
        let active = u32::from(request != 0);
        let (expected, replacement) = if active != 0 { (0x1000, 0x800) } else { (0x800, 0x1000) };
        if (*view).flags & 0x1800 != expected { return; }
        view_set_transition_mode(view, replacement);
        let vtable = (*view).vtable as usize as *const ViewTransitionVtable;
        ((*vtable).shown_changed)(view, active);
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
        // A callback can change both mode and unrelated flags: no post-call write.
        unsafe { (*view).flags ^= 0x8000_1800; }
    }

    #[test]
    fn mode_gating_normalization_and_callback_mutations() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::VIEW_TRANSITION_ACTIVE, 4096,
        ) else { return; };
        unsafe {
            let view = slab.cast::<ViewBase>();
            let table = slab.add(0x300).cast::<ViewTransitionVtable>();
            table.write(ViewTransitionVtable { preceding_slots: [0; 42], shown_changed: changed });
            for surrounding in [0, 0xa5a5_e7ff, 0xffff_e7ff] {
                for mode in [0, 0x800, 0x1000, 0x1800] {
                    for request in [0, 1, 2, 0x8000_0000, u32::MAX] {
                        let notify = if request == 0 && mode == 0x800 {
                            Some((0, 0x1000))
                        } else if request != 0 && mode == 0x1000 {
                            Some((1, 0x800))
                        } else { None };
                        (*view).flags = surrounding | mode;
                        // Ineligible modes must not dereference even a null table.
                        (*view).vtable = if notify.is_some() { table as usize as u32 } else { 0 };
                        CALLS.store(0, Ordering::Relaxed);
                        view_set_transition_active(view, request);
                        assert_eq!(CALLS.load(Ordering::Relaxed), usize::from(notify.is_some()));
                        if let Some((active, replacement)) = notify {
                            assert_eq!(OBSERVED_VIEW.load(Ordering::Relaxed), view as usize);
                            assert_eq!(OBSERVED_ACTIVE.load(Ordering::Relaxed), active);
                            assert_eq!(OBSERVED_FLAGS.load(Ordering::Relaxed), (surrounding | replacement) as usize);
                            assert_eq!((*view).flags, (surrounding | replacement) ^ 0x8000_1800);
                        } else {
                            assert_eq!((*view).flags, surrounding | mode);
                        }
                    }
                }
            }
        }
    }
}
