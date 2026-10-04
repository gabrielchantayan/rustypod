//! Three-state bounds selection — FUN_081dd648 @ 0x081dd648.
//!
//! Raw extent: 144 bytes; next function begins at 0x081dd6d8. Verified
//! incoming calls: two plain BL, zero predicated BL. Body: one direct BL
//! to ui_element_invalidate and one virtual BLX through slot +0x68.
//! Negative requests select state 2; requests above 2 select state 0.
//! An unchanged state returns 0 without accessing any child. Otherwise store
//! the state, copy the selected child's four bounds words at +0x80 onto the
//! stack, call the recipient's +0x68 method with that copy and mode 0, then
//! invalidate the owner and return 1.
//!
//! Deliberate deviations: repr(C) native pointers widen the trailing object
//! fields and vtable slots on hosts; target offsets remain 0x138..0x148 and
//! 0x68. Only two arguments are exposed: the saved r2/r3 words in the ARM
//! prologue are overwritten on every reachable changed-state path.

use crate::ui::invalidate::ui_element_invalidate;

#[repr(C)]
pub struct ThreeStateBoundsOwner {
    pub prefix: [u32; 0x138 / 4],
    pub state: i32,
    pub recipient: *mut BoundsRecipient,
    pub sources: [*const BoundsSource; 3],
}

#[repr(C)]
pub struct BoundsSource {
    pub prefix: [u32; 0x80 / 4],
    pub bounds: [u32; 4],
}

#[repr(C)]
pub struct BoundsRecipient {
    pub vtable: *const BoundsRecipientVtable,
}

#[repr(C)]
pub struct BoundsRecipientVtable {
    pub preceding_slots: [usize; 0x68 / 4],
    pub apply_bounds: unsafe extern "C" fn(*mut BoundsRecipient, *const [u32; 4], u32),
}

/// Select a normalized state; return whether it changed. All selected pointers
/// and the recipient's virtual method must be valid on the changed path.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_three_state_select_bounds(
    owner: *mut ThreeStateBoundsOwner,
    requested_state: i32,
) -> u32 {
    let state = if requested_state < 0 { 2 }
        else if requested_state > 2 { 0 } else { requested_state };
    if (*owner).state == state {
        return 0;
    }
    (*owner).state = state;
    let bounds = (*(*owner).sources[state as usize]).bounds;
    let recipient = (*owner).recipient;
    ((*(*recipient).vtable).apply_bounds)(recipient, &bounds, 0);
    ui_element_invalidate(owner.cast());
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[repr(C)]
    struct RecordingRecipient {
        base: BoundsRecipient,
        owner: *mut ThreeStateBoundsOwner,
        calls: u32,
        bounds: [u32; 4],
        state: i32,
    }

    unsafe extern "C" fn apply(recipient: *mut BoundsRecipient, bounds: *const [u32; 4], mode: u32) {
        let recording = &mut *recipient.cast::<RecordingRecipient>();
        assert_eq!(mode, 0);
        recording.calls += 1;
        recording.bounds = *bounds;
        recording.state = (*recording.owner).state;
        // Mutating the source must not mutate the stack-local argument.
        (*(*recording.owner).sources[recording.state as usize].cast_mut()).bounds = [99; 4];
        assert_eq!(*bounds, recording.bounds);
    }

    #[test]
    fn normalization_selection_and_store_before_callback() {
        let table = BoundsRecipientVtable { preceding_slots: [0; 26], apply_bounds: apply };
        for requested in [i32::MIN, -1, 0, 1, 2, 3, i32::MAX] {
            let expected = if requested < 0 { 2 } else if requested > 2 { 0 } else { requested };
            let mut sources = [
                BoundsSource { prefix: [0; 32], bounds: [0, 1, 2, 3] },
                BoundsSource { prefix: [0; 32], bounds: [4, 5, 6, 7] },
                BoundsSource { prefix: [0; 32], bounds: [8, 9, 10, u32::MAX] },
            ];
            let expected_bounds = sources[expected as usize].bounds;
            let mut owner = ThreeStateBoundsOwner {
                prefix: [0; 78], state: (expected + 1) % 3,
                recipient: ptr::null_mut(),
                sources: [ptr::addr_of!(sources[0]), ptr::addr_of!(sources[1]), ptr::addr_of!(sources[2])],
            };
            let mut recipient = RecordingRecipient {
                base: BoundsRecipient { vtable: &table }, owner: &mut owner,
                calls: 0, bounds: [0; 4], state: -1,
            };
            owner.recipient = &mut recipient.base;
            unsafe { assert_eq!(ui_three_state_select_bounds(&mut owner, requested), 1); }
            assert_eq!(owner.state, expected);
            assert_eq!(recipient.state, expected);
            assert_eq!(recipient.bounds, expected_bounds);
            assert_eq!(recipient.calls, 1);
            assert_eq!(sources[expected as usize].bounds, [99; 4]);
            // No child or recipient access when normalized state is unchanged.
            owner.recipient = ptr::null_mut();
            owner.sources = [ptr::null(); 3];
            unsafe { assert_eq!(ui_three_state_select_bounds(&mut owner, requested), 0); }
        }
    }
}
