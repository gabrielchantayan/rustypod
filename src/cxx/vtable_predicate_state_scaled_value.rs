//! Vtable-gated state-value scaling.
//!
//! `vtable_predicate_state_scaled_value` — original: `FUN_082a4290` @
//! **0x082a4290** (**56 bytes**, `0x082a4290..0x082a42c8`; the separately
//! linked next function starts at `0x082a42c8`).
//!
//! Decoding every ARM `B`/`BL` word in `osos.dec` finds **6 direct `bl` call
//! sites**, all unconditional (`cond = AL`), at 0x08114558, 0x08114dd4,
//! 0x081153a0, 0x08176428, 0x08177368, and 0x0821f378; there are no
//! predicated calls or direct tail branches. The body makes one indirect
//! `blx`, then tail-branches to `__rt_udiv` @ 0x08036f14.
//!
//! Algorithm: call the object's vtable slot `+0x08`; return zero when that
//! predicate is zero. Otherwise, load the u32 at the associated state object's
//! `+0x5c` and return its unsigned quotient by 1000. The predicate's identity
//! and the state-word unit are not recovered, so this port names only the
//! verified gating and scaling behavior. It reuses the same recovered object
//! prefix as `vtable_predicate_state_flag_set` at 0x082a4380. No deliberate
//! deviations.

use crate::cxx::vtable_predicate_state_flag::VtablePredicateObject;
#[cfg(test)]
use crate::cxx::vtable_predicate_state_flag::VtablePredicate;
use crate::runtime::rt_div::__rt_udiv;

const VTABLE_PREDICATE_SLOT: usize = 0x08 / 4;
const STATE_SCALED_VALUE_WORD: usize = 0x5c / 4;
const SCALE_DIVISOR: u32 = 1000;

/// Calls vtable slot `+0x08`, then divides the associated state's `+0x5c`
/// word by 1000 when the predicate succeeds.
///
/// # Safety
///
/// `object` must refer to a valid retail object and contain a callable vtable
/// predicate at `+0x08`. If that predicate returns nonzero, `object->state`
/// must point to a readable u32 at `+0x5c`. The original performs no NULL,
/// alignment, or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_predicate_state_scaled_value(
    object: *mut VtablePredicateObject,
) -> u32 {
    let predicate = object.read().vtable.add(VTABLE_PREDICATE_SLOT).read();
    if predicate(object) == 0 {
        return 0;
    }

    let value = object.read().state.cast::<u32>().add(STATE_SCALED_VALUE_WORD).read();
    __rt_udiv(value, SCALE_DIVISOR)
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;

    use crate::cxx::vtable_predicate_state_flag::VtablePredicateState;

    unsafe extern "C" fn unused_predicate(_: *mut VtablePredicateObject) -> u32 {
        panic!("the port selected the wrong vtable slot")
    }

    unsafe extern "C" fn not_ready(_: *mut VtablePredicateObject) -> u32 {
        0
    }

    unsafe extern "C" fn ready(_: *mut VtablePredicateObject) -> u32 {
        0xffff_ffff
    }

    static NOT_READY_VTABLE: [VtablePredicate; 3] = [unused_predicate, unused_predicate, not_ready];
    static READY_VTABLE: [VtablePredicate; 3] = [unused_predicate, unused_predicate, ready];

    #[test]
    fn returns_zero_without_touching_state_when_predicate_is_zero() {
        let mut object = VtablePredicateObject {
            vtable: NOT_READY_VTABLE.as_ptr(),
            unresolved_04: 0,
            state: core::ptr::null(),
        };

        assert_eq!(unsafe { vtable_predicate_state_scaled_value(&mut object) }, 0);
    }

    #[test]
    fn divides_any_nonzero_predicate_state_value_by_1000() {
        let mut state = VtablePredicateState {
            unresolved_before_flags: [0; 0xbc / 4],
            flags: 0,
        };
        let mut object = VtablePredicateObject {
            vtable: READY_VTABLE.as_ptr(),
            unresolved_04: 0,
            state: &state,
        };

        for value in [0, 1, 999, 1_000, 1_001, 0xffff_ffff] {
            state.unresolved_before_flags[STATE_SCALED_VALUE_WORD] = value;
            assert_eq!(unsafe { vtable_predicate_state_scaled_value(&mut object) }, value / SCALE_DIVISOR);
        }
    }
}
