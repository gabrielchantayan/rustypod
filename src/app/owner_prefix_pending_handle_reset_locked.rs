//! Resets the pending owner-prefix handle under its selected mutex.
//!
//! `owner_prefix_pending_handle_reset_locked` — `FUN_08214dbc` at
//! **0x08214dbc**, **36 bytes** (exclusive end `0x08214de0`, the next PUSH
//! prologue). Raw words contain three unconditional BLs, zero predicated BLs;
//! whole-image decoding finds two incoming plain BLs (0x0822b574, 0x0822b784)
//! and zero predicated incoming BLs.
//!
//! Acquires the state's mutex handoff, resets the owner-prefix state and pending
//! shared-cell handle, releases the currently selected mutex, and returns 1.
//! Deliberate deviations: none in this wrapper. Reuses the canonical mutex and
//! reset ports, including their documented host layout and resident-call seams.

use crate::app::owner_prefix_pending_handle_reset::owner_prefix_pending_handle_reset;
use crate::kernel::mutex_handoff::{mutex_handoff_lock, mutex_handoff_unlock, MutexHandoff};

/// Resets the state while protected by its selected mutex; always returns 1.
///
/// # Safety
/// `state` must satisfy `owner_prefix_pending_handle_reset`'s owner-prefix and
/// writable-tail contract and begin with a valid `MutexHandoff`. Its selected
/// mutex must remain valid through release, including any reset callbacks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_prefix_pending_handle_reset_locked(state: *mut u8) -> u32 {
    mutex_handoff_lock(state.cast::<MutexHandoff>());
    owner_prefix_pending_handle_reset(state);
    mutex_handoff_unlock(state.cast::<MutexHandoff>());
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::owner_prefix_vtable_slot_30_tail_dispatch::{OwnerPrefixVtableSlot30Receiver, OwnerPrefixVtableSlot30Vtable};
    use crate::kernel::sync_mutex::Mutex;
    use core::ptr;

    unsafe extern "C" fn mark_callback(receiver: *mut OwnerPrefixVtableSlot30Receiver) -> u32 {
        let state = receiver.cast::<u8>().add(0x2d8);
        // A non-success callback result must not escape the reset wrapper.
        state.add(0x2ef).write(0x73);
        0xffff_ffff
    }

    #[test]
    fn resets_dirty_and_empty_handles_with_embedded_and_external_selection() {
        let vtable = OwnerPrefixVtableSlot30Vtable {
            opaque_00_2c: [0; 12], dispatch: mark_callback,
        };
        for external in [false, true] {
            for pending in [0, 0xdead_beef] {
                // Native pointer alignment, enough space for both the owner prefix
                // and all bytes consumed by the real reset callee.
                let mut storage = [0u64; 256];
                let owner = storage.as_mut_ptr().cast::<OwnerPrefixVtableSlot30Receiver>();
                let mut selected = Mutex { sem_cell: ptr::null_mut(), unused: 0 };
                unsafe {
                    ptr::addr_of_mut!((*owner).vtable).write(&vtable);
                    let state = owner.cast::<u8>().add(0x2d8);
                    let handoff = state.cast::<MutexHandoff>();
                    handoff.write(MutexHandoff {
                        opaque: 0x1234,
                        bootstrap_mutex: Mutex { sem_cell: ptr::null_mut(), unused: 0 },
                        current_mutex: ptr::null_mut(),
                    });
                    (*handoff).current_mutex = if external { &mut selected } else {
                        ptr::addr_of_mut!((*handoff).bootstrap_mutex)
                    };
                    state.add(0x2ef).write(0xa5);
                    state.add(0x2f0).write(0xff);
                    state.add(0x2f1).write(0xff);
                    state.add(0x2f2).write(0xa5);
                    state.add(0x2f4).cast::<u32>().write(pending);
                    assert_eq!(owner_prefix_pending_handle_reset_locked(state), 1);
                    assert_eq!(state.add(0x2ef).read(), 0x73);
                    assert_eq!(state.add(0x2f0).read(), 1);
                    assert_eq!(state.add(0x2f1).read(), 0);
                    assert_eq!(state.add(0x2f2).read(), 0xa5);
                    assert_eq!(state.add(0x2f4).cast::<u32>().read(), 0);
                    assert_eq!((*handoff).opaque, 0x1234);
                }
            }
        }
    }
}
