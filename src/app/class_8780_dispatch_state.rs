//! Registry-class-0x8780 dispatch-state selector.
//!
//! `class_8780_dispatch_state` — original: `FUN_081a3ed4` @ **0x081a3ed4**
//! (52 bytes; thirteen ARM instructions, ending at `bx lr` @ 0x081a3f04; the
//! separately linked next function begins at 0x081a3f08). A complete decode of
//! every ARM `B`/`BL` immediate in `osos.dec` finds **10 direct, unconditional
//! `bl` call sites** (0x08126378, 0x0819b2f8, 0x081a2ebc, 0x081a2ef0,
//! 0x081a38a0, 0x081a3bfc, 0x081a4c2c, 0x081a4e9c, 0x081a4eec, and
//! 0x081a4f3c), with no predicated calls or direct `b` tails.
//!
//! Algorithm: choose a four-valued dispatch state from three bytes of the
//! otherwise unnamed class-0x8780 object. A nonzero priority gate at `+0x1c`
//! returns 3. Otherwise a zero secondary gate at `+0x8a` returns 0; a nonzero
//! secondary gate returns 1 when its associated byte at `+0x8c` is zero and 2
//! otherwise. Callers use states 0..=2 for alternate dispatches and state 3
//! as their common readiness gate.
//!
//! Deliberate deviations: none. The field names describe only this selector's
//! observed precedence; the class's business-level state meanings remain
//! unrecovered.

/// Observed bytes of the registry class-0x8780 object.
///
/// The constructor at 0x081a4f64 zeroes all three observed bytes. The unused
/// ranges preserve their target offsets without assuming identities for them.
#[repr(C)]
struct Class8780DispatchState {
    _before_priority_gate: [u8; 0x1c],
    priority_gate: u8,
    _before_secondary_gate: [u8; 0x8a - 0x1d],
    secondary_gate: u8,
    _before_secondary_value: u8,
    secondary_value: u8,
}

const _: [(); 0x8d] = [(); core::mem::size_of::<Class8780DispatchState>()];

/// class_8780_dispatch_state — original: `FUN_081a3ed4` @ **0x081a3ed4**
/// (52 bytes; 10 direct unconditional `bl` call sites).
///
/// # Safety
///
/// `object` must point to a readable class-0x8780 object through byte `+0x8c`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_8780_dispatch_state(object: *const u8) -> u32 {
    let state = &*object.cast::<Class8780DispatchState>();

    if state.priority_gate != 0 {
        3
    } else if state.secondary_gate == 0 {
        0
    } else if state.secondary_value == 0 {
        1
    } else {
        2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_each_dispatch_state_with_observed_precedence() {
        let cases = [
            (0, 0, 0, 0),
            (0, 0, u8::MAX, 0),
            (0, 1, 0, 1),
            (0, u8::MAX, 0, 1),
            (0, 1, 1, 2),
            (0, u8::MAX, u8::MAX, 2),
            (1, 0, 0, 3),
            (u8::MAX, 1, 1, 3),
        ];

        for (priority_gate, secondary_gate, secondary_value, expected) in cases {
            let object = Class8780DispatchState {
                _before_priority_gate: [0; 0x1c],
                priority_gate,
                _before_secondary_gate: [0; 0x8a - 0x1d],
                secondary_gate,
                _before_secondary_value: 0,
                secondary_value,
            };
            assert_eq!(
                unsafe { class_8780_dispatch_state((&object as *const Class8780DispatchState).cast()) },
                expected,
                "priority={priority_gate}, secondary_gate={secondary_gate}, secondary_value={secondary_value}"
            );
        }
    }
}
