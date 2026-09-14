//! Saturating action-index advance for the input-sequence state.
//!
//! `input_action_index_advance` — original: `FUN_08129b6c` @
//! **0x08129b6c** (24 bytes, `0x08129b6c..0x08129b84`; the separately linked
//! sibling begins at `0x08129b84`).
//!
//! The raw ARM body loads the word at `input_state + 0xb4`, increments it only
//! when it is below 31, stores the incremented value, then reloads and returns
//! that word. Input-sequence callers use the low byte as the action index when
//! queuing input actions. Decoding every aligned ARM B/BL immediate in
//! `osos.dec` finds six inbound direct calls, all unconditional plain `bl` at
//! `0x08129a70`, `0x08129fbc`, `0x08129fc8`, `0x08129fd4`, `0x0812a200`, and
//! `0x0812ae28`; there are no predicated forms, direct tail branches, or
//! aligned image-word references.
//!
//! Deliberate deviations: none. Volatile accesses preserve the raw body's
//! explicit post-store reload. The enclosing input-sequence state type is not
//! recovered, so this module models only its verified prefix and action-index
//! field.

use core::ptr;

#[repr(C)]
struct InputActionStateLayout {
    /// Opaque state through `+0xb3`.
    prefix: [u32; 45],
    /// `+0xb4` — action index used by input-sequence action dispatch.
    action_index: u32,
}

const _: [u8; 0xb8] = [0; core::mem::size_of::<InputActionStateLayout>()];
const _: [u8; 0xb4] = [0; core::mem::offset_of!(InputActionStateLayout, action_index)];

/// Advances the input sequence's action index without exceeding 31.
///
/// # Safety
///
/// `input_state` must point to a writable state containing an aligned `u32` at
/// offset `0xb4`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn input_action_index_advance(input_state: *mut u8) -> u32 {
    let state = input_state.cast::<InputActionStateLayout>();
    unsafe {
        let action_index = ptr::addr_of!((*state).action_index).read_volatile();
        if action_index < 31 {
            ptr::addr_of_mut!((*state).action_index).write_volatile(action_index + 1);
        }
        ptr::addr_of!((*state).action_index).read_volatile()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(action_index: u32) -> InputActionStateLayout {
        InputActionStateLayout {
            prefix: [0; 45],
            action_index,
        }
    }

    #[test]
    fn advances_action_indices_below_limit() {
        let mut state = fixture(0);

        let result = unsafe { input_action_index_advance(core::ptr::addr_of_mut!(state).cast()) };

        assert_eq!(result, 1);
        assert_eq!(state.action_index, 1);
    }

    #[test]
    fn saturates_at_limit_without_overflowing_larger_values() {
        let mut at_limit = fixture(31);
        let mut above_limit = fixture(u32::MAX);

        let limit_result = unsafe {
            input_action_index_advance(core::ptr::addr_of_mut!(at_limit).cast())
        };
        let above_result = unsafe {
            input_action_index_advance(core::ptr::addr_of_mut!(above_limit).cast())
        };

        assert_eq!(limit_result, 31);
        assert_eq!(at_limit.action_index, 31);
        assert_eq!(above_result, u32::MAX);
        assert_eq!(above_limit.action_index, u32::MAX);
    }
}
