//! Locked assignment of the controller's fixed record state.
//!
//! Original: `FUN_082081f8` @ `0x082081f8`, 44 bytes through
//! `0x08208224` (exclusive), where the next independent PUSH begins.
//! Raw A32 words verify two inbound plain BLs at 0x0822ab14 and 0x0822b798,
//! three outbound plain BLs, and no predicated BLs in either direction.
//! Acquires the mutex handoff, copies the 18 records and two trailing words
//! into the state at target +0x1c while preserving its leading word, releases
//! the selected mutex, and returns one regardless of the copier's return.
//!
//! Deliberate deviations: calls the three existing Rust ports directly.
//! Named repr(C) fields preserve target offsets while allowing native-width
//! mutex pointers on hosts; consequently the host state offset differs.

use crate::app::copy_eighteen_records_and_tail::copy_eighteen_records_and_tail;
use crate::kernel::mutex_handoff::{mutex_handoff_lock, mutex_handoff_unlock, MutexHandoff};

/// Target layout: handoff at +0, three opaque words at +0x10, state at +0x1c.
#[repr(C)]
pub struct ControllerRecordState {
    pub handoff: MutexHandoff,
    pub opaque: [u32; 3],
    pub state: [u32; 0x294 / 4],
}

/// Assign all state words except the destination's leading word under its lock.
///
/// # Safety
/// `controller` must be writable and its handoff must name valid mutexes.
/// `source` must be aligned and readable for 0x294 bytes, with overlap valid
/// for the existing forward record copier. Concurrent access requires the
/// same selected lock; the selected pointer must remain valid while held.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn locked_controller_records_copy(
    controller: *mut ControllerRecordState,
    source: *const u8,
) -> u32 {
    let handoff = core::ptr::addr_of_mut!((*controller).handoff);
    mutex_handoff_lock(handoff);
    copy_eighteen_records_and_tail(core::ptr::addr_of_mut!((*controller).state).cast(), source);
    mutex_handoff_unlock(handoff);
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::sync_mutex::Mutex;

    #[test]
    fn preserves_header_and_leading_word_with_embedded_or_selected_lock() {
        for selected in [false, true] {
            let mut handle = 0;
            let mut separate = Mutex { sem_cell: &mut handle, unused: 0 };
            let mut controller = ControllerRecordState {
                handoff: MutexHandoff {
                    opaque: 0x12345678,
                    bootstrap_mutex: Mutex { sem_cell: &mut handle, unused: 0 },
                    current_mutex: core::ptr::null_mut(),
                },
                opaque: [0xdeadbeef, 0xabcdef01, 0x76543210],
                state: [0xfeedface; 0x294 / 4],
            };
            controller.handoff.current_mutex = if selected {
                &mut separate
            } else {
                core::ptr::addr_of_mut!(controller.handoff.bootstrap_mutex)
            };
            let source: [u32; 0x294 / 4] = core::array::from_fn(|i| (i as u32).wrapping_mul(0x01020304));
            let current = controller.handoff.current_mutex;
            assert_eq!(unsafe { locked_controller_records_copy(&mut controller, source.as_ptr().cast()) }, 1);
            assert_eq!(controller.state[0], 0xfeedface);
            assert_eq!(&controller.state[1..], &source[1..]);
            assert_eq!(controller.opaque, [0xdeadbeef, 0xabcdef01, 0x76543210]);
            assert_eq!(controller.handoff.opaque, 0x12345678);
            assert_eq!(controller.handoff.current_mutex, current);
            // Reassignment from the same state is valid and must preserve it.
            let snapshot = controller.state;
            let same = controller.state.as_ptr().cast();
            assert_eq!(unsafe { locked_controller_records_copy(&mut controller, same) }, 1);
            assert_eq!(controller.state, snapshot);
        }
    }
}
