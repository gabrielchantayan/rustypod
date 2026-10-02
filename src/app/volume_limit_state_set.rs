//! `volume_limit_state_set` — `FUN_0827f6cc` @ 0x0827f6cc, 32 bytes.
//! The next real function starts at 0x0827f6ec. Raw A32 words verify zero
//! outgoing plain BLs and one BLEQ to 0x0827f748; whole-image decoding finds
//! one incoming plain BL (0x0820e8e4) and one BLEQ (0x08202e4c).
//!
//! Store the new volume-limit state at +0xb4. For state 1, invoke the resident
//! routine with (object, 1), then reload and return the possibly changed state.
//! Deliberate deviation: no behavior change; the unnamed, unported resident
//! routine uses an exact-address target seam and a replaceable host seam.

const STATE_WORD: usize = 0xb4 / 4;
type ResidentStateAction = unsafe extern "C" fn(*mut u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_action(_: *mut u32, _: u32) -> u32 {
    panic!("volume_limit_state_set requires resident routine 0x0827f748")
}

#[cfg(not(target_os = "none"))]
pub static mut VOLUME_LIMIT_STATE_ACTION: ResidentStateAction = missing_action;

#[inline(always)]
unsafe fn set_with(object: *mut u32, state: u32, action: impl FnOnce(*mut u32, u32)) -> u32 {
    let field = unsafe { object.add(STATE_WORD) };
    unsafe { field.write_volatile(state) };
    if state == 1 { action(object, state); }
    unsafe { field.read_volatile() }
}

/// Sets the state and returns the post-action state, not the action's result.
///
/// # Safety
/// `object` must contain an aligned writable word at +0xb4 and, for state 1,
/// satisfy the resident routine's complete object contract. No NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn volume_limit_state_set(object: *mut u32, state: u32) -> u32 {
    unsafe { set_with(object, state, |object, state| {
        #[cfg(target_os = "none")]
        let action: ResidentStateAction = core::mem::transmute(0x0827_f748usize);
        #[cfg(not(target_os = "none"))]
        let action = core::ptr::addr_of!(VOLUME_LIMIT_STATE_ACTION).read_volatile();
        action(object, state);
    }) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_trigger_states_preserve_all_other_words() {
        for state in [0, 2, 3, 0x8000_0000, u32::MAX] {
            let mut object = [0xa5a5_5a5a; STATE_WORD + 2];
            let result = unsafe { set_with(object.as_mut_ptr(), state, |_, _| panic!("unexpected action")) };
            assert_eq!(result, state);
            assert_eq!(object[STATE_WORD], state);
            assert!(object[..STATE_WORD].iter().all(|&word| word == 0xa5a5_5a5a));
            assert_eq!(object[STATE_WORD + 1], 0xa5a5_5a5a);
        }
    }

    #[test]
    fn trigger_is_stored_before_action_and_result_is_reloaded() {
        for final_state in [0, 1, 3, u32::MAX] {
            let mut object = [0u32; STATE_WORD + 1];
            object[STATE_WORD] = 3;
            let result = unsafe { set_with(object.as_mut_ptr(), 1, |object, state| {
                assert_eq!(state, 1);
                assert_eq!(object.add(STATE_WORD).read(), 1);
                object.add(STATE_WORD).write(final_state);
            }) };
            assert_eq!(result, final_state);
            assert_eq!(object[STATE_WORD], final_state);
        }
    }
}
