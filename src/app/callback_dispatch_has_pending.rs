//! `callback_dispatch_has_pending` — original: `FUN_08124cd0` @ `0x08124cd0`
//! (28 bytes, `0x08124cd0..0x08124cec`; the next independently decoded
//! function starts at `0x08124cec`).
//!
//! The function loads the callback-state pointer at `context+0x04`. A NULL
//! state returns false; otherwise, it returns whether that state's signed word
//! at `+0x04` is strictly positive. The raw ARM contains no call instruction.
//! It has four direct incoming `bl` call sites, all unconditional
//! (0x081576ec, 0x0815792c, 0x08157a28, and 0x08157be0), and no predicated
//! `bl` call sites, verified from the decoded ARM words.
//!
//! Deliberate deviation: target pointers occupy the original four-byte fields;
//! `#[repr(C)]` expresses their roles on 64-bit hosts, where their byte offsets
//! are naturally wider. The ARM source has no NULL guard for `context`, so this
//! function preserves that precondition.

/// Callback-dispatch context containing its optional pending state.
#[repr(C)]
pub struct CallbackDispatchContext {
    pub unresolved_00: u32,
    pub pending_state: *const CallbackPendingState,
}

/// Recovered pending-state fields used by the availability predicate.
#[repr(C)]
pub struct CallbackPendingState {
    pub unresolved_00: u32,
    pub pending_count: i32,
}

/// Returns one exactly when `context` has a pending state with a positive count.
///
/// # Safety
///
/// `context` must point to a readable [`CallbackDispatchContext`]. A non-NULL
/// `pending_state` must point to a readable [`CallbackPendingState`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn callback_dispatch_has_pending(
    context: *const CallbackDispatchContext,
) -> u32 {
    let pending_state = unsafe { (*context).pending_state };
    if pending_state.is_null() {
        0
    } else {
        (unsafe { (*pending_state).pending_count } > 0) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn null_pending_state_is_not_pending() {
        let context = CallbackDispatchContext {
            unresolved_00: 0,
            pending_state: core::ptr::null(),
        };

        assert_eq!(unsafe { callback_dispatch_has_pending(&context) }, 0);
    }

    #[test]
    fn non_positive_counts_are_not_pending() {
        for pending_count in [i32::MIN, -1, 0] {
            let state = CallbackPendingState { unresolved_00: 0, pending_count };
            let context = CallbackDispatchContext {
                unresolved_00: 0,
                pending_state: &state,
            };
            assert_eq!(unsafe { callback_dispatch_has_pending(&context) }, 0);
        }
    }

    #[test]
    fn positive_counts_are_pending() {
        for pending_count in [1, i32::MAX] {
            let state = CallbackPendingState { unresolved_00: 0, pending_count };
            let context = CallbackDispatchContext {
                unresolved_00: 0,
                pending_state: &state,
            };
            assert_eq!(unsafe { callback_dispatch_has_pending(&context) }, 1);
        }
    }
}
