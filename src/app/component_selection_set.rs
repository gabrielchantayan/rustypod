//! Component selection setter — `FUN_0820db60` @ **0x0820db60**.
//! True extent **136 bytes**, ending at 0x0820dbe8: 132 instruction bytes
//! and the 0x4b42534c message-code literal at 0x0820dbe4. The next function
//! starts with push {r4,r5,r6,lr}. Verified inbound calls: **2 plain BL,
//! 0 predicated BL** (0x08130934, 0x0820dc40). Body: 3 plain BL, 0
//! predicated BL, and a tail B to three_word_message_post at 0x0820dbe0.
//!
//! Reject negative indices without touching the owner; reject indices at or
//! above the component's signed slot-08 result. Store the selection, extend
//! its lower/upper endpoints with inclusive comparisons (lower wins), and
//! update the endpoint flag only when an endpoint changes. Invalidate the
//! element; optionally obtain the slot-0c payload and post owner/payload/code.
//!
//! Deviations: typed Rust calls replace tail branches. The opaque component
//! methods retain their existing slot-based names. Return usize preserves the
//! original path-dependent r0 (owner, component count, or dispatch result),
//! including full host pointers. Host layouts widen pointers through repr(C);
//! target-only assertions enforce firmware offsets. No new retail seams.

use crate::cxx::component_vtable_slot_08_tail_dispatch::{
    component_vtable_slot_08_tail_dispatch, ComponentVtableSlot08Owner,
};
use crate::cxx::component_vtable_slot_12_payload_tail_dispatch::{
    component_vtable_slot_12_payload_tail_dispatch, ComponentVtableSlot12PayloadOwner,
};
use crate::ui::invalidate::ui_element_invalidate;
use crate::app::three_word_message_post::three_word_message_post;

/// Component owner and its selection interval. Opaque prefix remains untouched.
#[repr(C)]
pub struct ComponentSelection {
    pub owner: ComponentVtableSlot12PayloadOwner,
    pub lower: i32,
    pub upper: i32,
    pub lower_endpoint: u8,
    pub padding: [u8; 3],
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x1dc] = [0; core::mem::offset_of!(ComponentSelection, lower)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x1e0] = [0; core::mem::offset_of!(ComponentSelection, upper)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x1e4] = [0; core::mem::offset_of!(ComponentSelection, lower_endpoint)];

macro_rules! selection_body {
    ($state:expr, $index:expr, $notify:expr; $count:expr, $invalidate:expr, $payload:expr, $post:expr) => {{
        let state: *mut ComponentSelection = $state;
        let index: i32 = $index;
        if index < 0 {
            state as usize
        } else {
            let count: u32 = ($count)(state);
            if (count as i32) <= index {
                count as usize
            } else {
                (*state).owner.payload = index as u32;
                if index <= (*state).lower {
                    (*state).lower = index;
                    (*state).lower_endpoint = 1;
                } else if index >= (*state).upper {
                    (*state).upper = index;
                    (*state).lower_endpoint = 0;
                }
                let result: usize = ($invalidate)(state);
                if $notify == 0 {
                    result
                } else {
                    let payload: u32 = ($payload)(state);
                    ($post)(state as usize as u32, payload, 0x4b42_534c, 0) as usize
                }
            }
        }
    }};
}

/// Set a component selection and optionally emit its selection message.
///
/// # Safety
/// For nonnegative indices, state must contain a valid component/vtable.
/// For accepted indices it must be writable and a fully initialized UI element;
/// notification additionally requires the message arena and dispatcher.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn component_selection_set(
    state: *mut ComponentSelection,
    index: i32,
    notify: u32,
) -> usize {
    selection_body!(state, index, notify;
        |s: *mut ComponentSelection| component_vtable_slot_08_tail_dispatch(s.cast::<ComponentVtableSlot08Owner>()),
        |s: *mut ComponentSelection| ui_element_invalidate(s.cast()) as usize,
        |s: *mut ComponentSelection| component_vtable_slot_12_payload_tail_dispatch(s.cast()),
        three_word_message_post
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(lower: i32, upper: i32) -> ComponentSelection {
        ComponentSelection {
            owner: ComponentVtableSlot12PayloadOwner {
                opaque_00_bc: [0; 48], component: core::ptr::null_mut(),
                opaque_c4_1d4: [0; 69], payload: 99,
            },
            lower, upper, lower_endpoint: 0x7e, padding: [0xa5; 3],
        }
    }

    #[test]
    fn rejected_indices_preserve_state_and_signed_count() {
        for (index, count) in [(-1, 10), (i32::MIN, 10), (10, 10), (11, 10), (0, 0), (0, 0x8000_0000), (0, u32::MAX)] {
            let mut s = state(3, 7);
            let expected = if index < 0 { &mut s as *mut _ as usize } else { count as usize };
            let actual = unsafe { selection_body!(&mut s, index, 1;
                |_: *mut ComponentSelection| { assert!(index >= 0); count },
                |_: *mut ComponentSelection| -> usize { panic!("rejected index invalidated") },
                |_: *mut ComponentSelection| -> u32 { panic!("rejected index dispatched") },
                |_: u32, _: u32, _: u32, _: u32| -> u32 { panic!("rejected index posted") }
            ) };
            assert_eq!(actual, expected);
            assert_eq!((s.owner.payload, s.lower, s.upper, s.lower_endpoint), (99, 3, 7, 0x7e));
        }
    }

    #[test]
    fn inclusive_endpoints_interior_and_lower_precedence() {
        for (lower, upper, index, want_lower, want_upper, flag) in [
            (3, 7, 0, 0, 7, 1), (3, 7, 3, 3, 7, 1),
            (3, 7, 5, 3, 7, 0x7e), (3, 7, 7, 3, 7, 0),
            (3, 7, 9, 3, 9, 0), (7, 3, 5, 5, 3, 1),
        ] {
            let mut s = state(lower, upper);
            let result = unsafe { selection_body!(&mut s, index, 0;
                |_: *mut ComponentSelection| 10u32,
                |p: *mut ComponentSelection| {
                    assert_eq!((*p).owner.payload, index as u32);
                    assert_eq!(((*p).lower, (*p).upper, (*p).lower_endpoint), (want_lower, want_upper, flag));
                    p as usize
                },
                |_: *mut ComponentSelection| -> u32 { panic!("notification disabled") },
                |_: u32, _: u32, _: u32, _: u32| -> u32 { panic!("notification disabled") }
            ) };
            assert_eq!(result, &mut s as *mut _ as usize);
            assert_eq!(s.padding, [0xa5; 3]);
        }
    }

    #[test]
    fn notification_observes_updated_selection_after_invalidation() {
        let mut s = state(3, 7);
        let invalidated = core::cell::Cell::new(false);
        let result = unsafe { selection_body!(&mut s, 8, u32::MAX;
            |_: *mut ComponentSelection| 10u32,
            |_: *mut ComponentSelection| { invalidated.set(true); 123usize },
            |p: *mut ComponentSelection| {
                assert!(invalidated.get());
                assert_eq!(((*p).owner.payload, (*p).upper, (*p).lower_endpoint), (8, 8, 0));
                0xdead_beefu32
            },
            |owner: u32, payload: u32, code: u32, flag: u32| {
                assert_eq!(owner, &mut s as *mut _ as usize as u32);
                assert_eq!((payload, code, flag), (0xdead_beef, 0x4b42_534c, 0));
                0xface_cafeu32
            }
        ) };
        assert_eq!(result, 0xface_cafe);
    }
}
