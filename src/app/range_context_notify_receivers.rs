//! `range_context_notify_receivers` — `FUN_08140378` @ 0x08140378.
//! True extent: 84 bytes, 0x08140378..0x081403cc; the next function starts
//! with `ldr r0, [pc, #4]`. Raw A32 has one outbound plain BL, no predicated
//! BLs, and two BLXNE calls. Inbound BLs: one plain at 0x081e86a0 and one
//! predicated at 0x081dd010.
//!
//! Construct a 64-byte RangeState from context word 7 with resolution 1.
//! Notify non-null receivers at words 13 then 14 through vtable slot 3,
//! passing the same mutable state to each. Reload the second receiver after
//! the first callback; callbacks may replace it or modify the state.
//! Deviations: reuse the ported constructor (including its retained stock
//! configuration boundary). Untouched state words remain uninitialized.
//! Tests inject dispatch into the inlined core to avoid host code-pointer
//! truncation; the firmware path uses target-width object/vtable words.

use crate::util::range_state::{range_state_construct, RangeState};

#[inline(always)]
unsafe fn notify(
    context: *mut u32,
    mut dispatch: impl FnMut(u32, *mut RangeState),
) {
    let mut state = core::mem::MaybeUninit::<RangeState>::uninit();
    range_state_construct(state.as_mut_ptr(), context.add(7), 1);
    let first = context.add(13).read_volatile();
    if first != 0 {
        dispatch(first, state.as_mut_ptr());
    }
    let second = context.add(14).read_volatile();
    if second != 0 {
        dispatch(second, state.as_mut_ptr());
    }
}

/// # Safety
/// `context` must be aligned and readable through word 14. Nonzero receiver
/// words must point to live objects with valid target-width vtables and a
/// slot-3 method of ABI `void(receiver, RangeState *)`. Callbacks must only
/// read initialized state fields, or initialize other fields before reading.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn range_context_notify_receivers(context: *mut u32) {
    notify(context, |receiver, state| {
        let receiver = receiver as usize as *mut u32;
        let table = receiver.read() as usize as *const u32;
        let callback: unsafe extern "C" fn(*mut u32, *mut RangeState) =
            core::mem::transmute(table.add(3).read() as usize);
        callback(receiver, state);
    });
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn optional_receivers_preserve_order_and_share_state() {
        for (first, second) in [(0, 0), (11, 0), (0, 22), (11, 22), (11, 11)] {
            let mut context = [0u32; 15];
            context[13] = first;
            context[14] = second;
            let mut seen = std::vec::Vec::new();
            let mut previous = core::ptr::null_mut();
            unsafe { notify(context.as_mut_ptr(), |receiver, state| {
                if seen.is_empty() {
                    assert_eq!((*state).current_value, 0);
                    assert_eq!((*state).resolution, u32::MAX);
                    assert_eq!((*state).bucket_bounds, [[0; 2]; 4]);
                    previous = state;
                } else {
                    assert_eq!(state, previous);
                    assert_eq!((*state).current_value, 123);
                }
                (*state).current_value = 123;
                seen.push(receiver);
            }); }
            let expected: std::vec::Vec<_> = [first, second].into_iter()
                .filter(|receiver| *receiver != 0).collect();
            assert_eq!(seen, expected);
        }
    }

    #[test]
    fn first_callback_can_replace_remove_or_install_second_receiver() {
        for (old, replacement) in [(22, 33), (22, 0), (0, 33)] {
            let mut context = [0u32; 15];
            context[13] = 11;
            context[14] = old;
            let context = context.as_mut_ptr();
            let mut seen = std::vec::Vec::new();
            unsafe { notify(context, |receiver, state| {
                if seen.is_empty() {
                    context.add(14).write(replacement);
                    (*state).bucket_bounds[3] = [17, 29];
                } else {
                    assert_eq!((*state).bucket_bounds[3], [17, 29]);
                }
                seen.push(receiver);
            }); }
            assert_eq!(seen, if replacement == 0 { std::vec![11] }
                else { std::vec![11, replacement] });
        }
    }
}
