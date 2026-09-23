//! Aggregate selected handle metrics for an active UI object.
//!
//! `ui_state_dependent_handle_metric` — original: `FUN_081323ac` @
//! **0x081323ac**, 152 bytes (`0x081323ac..0x08132444`; the next separately
//! linked function begins at `0x08132444`). Raw ARM decoding finds three
//! direct inbound `bl` call sites, all unconditional, and no predicated
//! direct inbound `bl` call sites.
//!
//! # Algorithm
//!
//! An inactive object returns zero. An active object selects its first metric
//! when state byte `+0x1a` is 2, 5, or 7; it additionally selects the second
//! metric for states 0, 5, or 7 and the third for states 1, 5, or 7. Each
//! selected metric is word `+4` of the object reached through the
//! NULL-guarded handle at `+0x2c`, `+0x30`, or `+0x34` respectively.
//!
//! # Deliberate deviations
//!
//! The retail body calls three small, separately linked state predicates.
//! Their behavior is recovered directly from their raw ARM instructions and
//! inlined here rather than creating unverified callee seams. The existing
//! `handle_deref_or_null` port supplies the verified shared handle operation.

use crate::cxx::handle::handle_deref_or_null;

const ACTIVE_OFFSET: usize = 0x19;
const STATE_OFFSET: usize = 0x1a;
const FIRST_METRIC_HANDLE: usize = 0;
const SECOND_METRIC_HANDLE: usize = 1;
const THIRD_METRIC_HANDLE: usize = 2;

/// Target-layout prefix for [`ui_state_dependent_handle_metric`]. Pointer
/// fields intentionally remain packed: they are four bytes apart on ARM and
/// native-width apart in host fixtures.
#[repr(C, packed)]
pub struct StateDependentHandleMetricObject {
    _before_active: [u8; ACTIVE_OFFSET],
    active: u8,
    state: u8,
    _before_handles: [u8; 0x2c - STATE_OFFSET - 1],
    metric_handles: [*const *const u8; 3],
}
unsafe fn metric_handle_slot(object: *const StateDependentHandleMetricObject, index: usize) -> *const *const *const u8 {
    core::ptr::addr_of!((*object).metric_handles[index])
}

#[inline(always)]
unsafe fn metric_value(slot: *const *const *const u8) -> u32 {
    let target = handle_deref_or_null(slot.cast()).cast_const();
    #[cfg(target_os = "none")]
    {
        target.cast::<u32>().add(1).read()
    }
    #[cfg(not(target_os = "none"))]
    {
        target.cast::<usize>().add(1).read() as u32
    }
}

/// Returns the sum of the metrics selected by the object's active state.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_state_dependent_handle_metric(object: *const StateDependentHandleMetricObject) -> u32 {
    if core::ptr::addr_of!((*object).active).read() == 0 {
        return 0;
    }

    let state = core::ptr::addr_of!((*object).state).read();
    let mut total = 0;
    if state == 7 || state == 5 || state == 2 {
        total = metric_value(metric_handle_slot(object, FIRST_METRIC_HANDLE));
    }
    if state == 7 || state == 5 || state == 0 {
        total = total.wrapping_add(metric_value(metric_handle_slot(object, SECOND_METRIC_HANDLE)));
    }
    if state == 7 || state == 5 || state == 1 {
        total = total.wrapping_add(metric_value(metric_handle_slot(object, THIRD_METRIC_HANDLE)));
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metric_target(value: u32) -> [usize; 2] {
        [0, value as usize]
    }

    fn fixture(active: u8, state: u8, first: *const *const u8, second: *const *const u8, third: *const *const u8) -> StateDependentHandleMetricObject {
        StateDependentHandleMetricObject {
            _before_active: [0; ACTIVE_OFFSET],
            active,
            state,
            _before_handles: [0; 0x2c - STATE_OFFSET - 1],
            metric_handles: [first, second, third],
        }
    }

    #[test]
    fn selects_the_three_state_dependent_metric_combinations() {
        let first_target = metric_target(11);
        let second_target = metric_target(23);
        let third_target = metric_target(37);
        let first = first_target.as_ptr().cast::<u8>();
        let second = second_target.as_ptr().cast::<u8>();
        let third = third_target.as_ptr().cast::<u8>();
        let mut object = fixture(1, 0, &first, &second, &third);

        for (state, expected) in [(0, 23), (1, 37), (2, 11), (5, 71), (7, 71), (3, 0), (6, 0)] {
            object.state = state;
            assert_eq!(unsafe { ui_state_dependent_handle_metric(&object) }, expected);
        }
    }

    #[test]
    fn inactive_object_never_dereferences_metric_handles() {
        let object = fixture(0, 7, core::ptr::null(), core::ptr::null(), core::ptr::null());
        assert_eq!(unsafe { ui_state_dependent_handle_metric(&object) }, 0);
    }
}
