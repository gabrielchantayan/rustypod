//! Refresh the controller callback and query an unblocked selection's metric.
//!
//! Original: `FUN_081314ac` at `0x081314ac`, 80 bytes, ending at
//! `0x081314fc` (the next function's push). Raw aligned ARM-word decoding
//! verifies two incoming plain BLs (0x08130964, 0x081315d8), six outgoing
//! plain BLs, and zero predicated BLs in either direction.
//!
//! Read the owner's selection at +0xbc; its bytes +0x64/+0x6c choose the
//! controller callback's mode. When both are zero, query the state-dependent
//! handle metric, reload the selection, and read +0x19 if that metric is zero.
//! Always return one (event handled). The final byte read is absent from
//! Ghidra's C but present in raw instructions at 0x081314ec/0x081314f0.
//!
//! Deviations: native-width pointers in the host owner layout; the existing
//! singleton accessor is host-injected because its registry requires setup.
//! The otherwise discarded final byte uses a volatile read to retain access.

use super::object_bytes_64_or_6c_nonzero::object_bytes_64_or_6c_nonzero;
use super::media_now_playing_controller_noop::media_now_playing_controller_noop;
use crate::ui::state_dependent_handle_metric::ui_state_dependent_handle_metric;

#[repr(C)]
pub struct SelectionMetricOwner {
    pub prefix: [u32; 0xbc / 4],
    pub selection: *const u8,
}

#[cfg(not(target_os = "none"))]
pub static mut SELECTION_METRIC_CONTROLLER: unsafe extern "C" fn() -> *mut u8 = missing_controller;
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_controller() -> *mut u8 { panic!("install selection metric controller lookup") }

/// # Safety
/// Owner and selection must satisfy the predicate and metric layouts, including
/// valid handles for active states. Host lookup installation must be serialized.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn selection_metric_refresh(owner: *const SelectionMetricOwner) -> u32 {
    let selection = core::ptr::addr_of!((*owner).selection).read();
    let blocked = object_bytes_64_or_6c_nonzero(selection);
    #[cfg(target_os = "none")]
    let controller = super::registry::instance_of_class_3280();
    #[cfg(not(target_os = "none"))]
    let controller = SELECTION_METRIC_CONTROLLER();
    media_now_playing_controller_noop(controller.cast(), blocked);
    if blocked == 0 {
        let selection = core::ptr::addr_of!((*owner).selection).read();
        if ui_state_dependent_handle_metric(selection.cast()) == 0 {
            let selection = core::ptr::addr_of!((*owner).selection).read();
            selection.add(0x19).read_volatile();
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    unsafe extern "C" fn controller() -> *mut u8 { core::ptr::null_mut() }

    #[test]
    fn handles_blocked_invalid_handles_and_unblocked_zero_metrics() {
        let _lock = LOCK.lock();
        unsafe {
            let saved = SELECTION_METRIC_CONTROLLER;
            SELECTION_METRIC_CONTROLLER = controller;
            let mut storage = [0usize; 32];
            let selection = storage.as_mut_ptr().cast::<u8>();
            let owner = SelectionMetricOwner { prefix: [0; 0xbc / 4], selection };
            for (active, state, byte64, byte6c) in [
                (1, 5, 1, 0), (1, 5, 0, 255), (1, 5, 128, 255),
                (0, 5, 0, 0), (1, 3, 0, 0), (255, 255, 0, 0),
            ] {
                selection.add(0x19).write(active);
                selection.add(0x1a).write(state);
                selection.add(0x64).write(byte64);
                selection.add(0x6c).write(byte6c);
                let before = storage;
                assert_eq!(selection_metric_refresh(&owner), 1);
                assert_eq!(storage, before);
            }
            SELECTION_METRIC_CONTROLLER = saved;
        }
    }
}
