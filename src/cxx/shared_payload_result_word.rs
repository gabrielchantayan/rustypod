//! Shared payload result word — retailOS `FUN_08143458` @ `0x08143458`.
//!
//! Raw ARM occupies exactly 28 bytes, `0x08143458..0x08143473`; the `push`
//! prologue at `0x08143474` establishes the next real function boundary.
//! Complete A32 decoding finds three inbound plain `bl` call sites and zero
//! predicated inbound `bl` forms. For shared-cell states zero and one, it
//! follows the payload's +0x40 pointer and returns that object's +0x14 word;
//! every other state returns zero. The original tail-branches to the identical
//! lookup helper at `0x0813e5f4`; this port inlines that verified leaf rather
//! than introducing an otherwise-unused call seam. Pointer fields widen on
//! hosts, so `repr(C)` fields model target words without host byte offsets.

use crate::cxx::shared_cell::SharedCell;

#[repr(C)]
pub struct SharedPayloadSlot {
    cell: *const SharedCell,
    state: u32,
}

#[repr(C)]
pub struct SharedPayload {
    _prefix: [u32; 16],
    result: *const SharedPayloadResult,
}

#[repr(C)]
pub struct SharedPayloadResult {
    _prefix: [u32; 5],
    value: u32,
}

/// Returns the result word for a ready shared payload.
///
/// # Safety
/// `slot` must be a valid, aligned shared-cell slot. For state zero or one,
/// its non-NULL cell must contain a `SharedPayload` whose non-NULL `result`
/// points to a readable [`SharedPayloadResult`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.shared_payload_result_word")]
#[inline(never)]
pub unsafe extern "C" fn shared_payload_result_word(slot: *const SharedPayloadSlot) -> u32 {
    let state = unsafe { (*slot).state };
    if state > 1 {
        return 0;
    }

    let cell = unsafe { (*slot).cell };
    let payload = unsafe { (*cell).value as *const SharedPayload };
    let result = unsafe { (*payload).result };
    if result.is_null() {
        0
    } else {
        unsafe { (*result).value }
    }
}

#[cfg(test)]
mod tests {
    use super::{shared_payload_result_word, SharedPayload, SharedPayloadResult, SharedPayloadSlot};
    use crate::cxx::shared_cell::SharedCell;

    fn result_for(state: u32, result: *const SharedPayloadResult) -> u32 {
        let payload = SharedPayload {
            _prefix: [0; 16],
            result,
        };
        let cell = SharedCell {
            value: core::ptr::addr_of!(payload) as usize,
            refcount: 1,
        };
        let slot = SharedPayloadSlot {
            cell: core::ptr::addr_of!(cell),
            state,
        };
        unsafe { shared_payload_result_word(&slot) }
    }

    #[test]
    fn ready_states_return_nested_result_word() {
        let result = SharedPayloadResult {
            _prefix: [0; 5],
            value: 0xfeed_beef,
        };

        for state in [0, 1] {
            assert_eq!(result_for(state, core::ptr::addr_of!(result)), 0xfeed_beef);
        }
    }

    #[test]
    fn ready_state_with_no_result_returns_zero() {
        assert_eq!(result_for(0, core::ptr::null()), 0);
    }

    #[test]
    fn other_states_do_not_dereference_slot() {
        for state in [2, 3, u32::MAX] {
            let slot = SharedPayloadSlot {
                cell: core::ptr::dangling::<SharedCell>(),
                state,
            };
            assert_eq!(unsafe { shared_payload_result_word(&slot) }, 0);
        }
    }
}
