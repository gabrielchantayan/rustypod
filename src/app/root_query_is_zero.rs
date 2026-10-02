//! Root-query zero predicate.
//!
//! `root_query_is_zero` — original `FUN_08289a40` @ **0x08289a40**,
//! **28 bytes**, `0x08289a40..0x08289a5c`. The next independent entry
//! at 0x08289a5c is `bx lr`, not part of this function's returning body.
//! Raw aligned ARM decoding verifies two incoming plain BLs (0x08289718,
//! 0x08289c80), zero predicated BLs, and one outgoing plain BL at
//! 0x08289a48 to the already ported `root_slot_190_query` (0x081115e4).
//! Loads the root pointer at receiver +0x28, queries its +0x888 subobject's
//! vtable slot +0x190, and returns exactly 1 for zero, otherwise 0.
//! Deliberate deviations: native host pointers widen the receiver's root
//! field; target layout is checked. No behavioral deviations or NULL guards.

use crate::app::root_slot_190_query::{root_slot_190_query, RootSlot190QueryRoot};

/// Receiver prefix; the firmware root pointer occupies word ten.
#[repr(C)]
pub struct RootQueryReceiver {
    pub opaque_00_27: [u32; 10],
    pub root: *mut RootSlot190QueryRoot,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x28] = [0; core::mem::offset_of!(RootQueryReceiver, root)];

/// Returns whether the receiver's root query result is zero.
///
/// # Safety
/// `receiver` must be readable and its root must satisfy
/// [`root_slot_190_query`]'s safety contract. Neither pointer may be NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn root_query_is_zero(receiver: *const RootQueryReceiver) -> u32 {
    let root = unsafe { (*receiver).root };
    (unsafe { root_slot_190_query(root) } == 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::root_slot_190_query::{
        RootSlot190QueryCallback, RootSlot190QuerySubobject,
        ROOT_SLOT_190_QUERY_SLOT, ROOT_SLOT_190_SUBOBJECT_OFFSET,
    };

    #[repr(C)]
    struct QueryFixture {
        vtable: *const RootSlot190QueryCallback,
        result: u32,
        calls: u32,
    }

    unsafe extern "C" fn query(subobject: *mut RootSlot190QuerySubobject) -> u32 {
        let fixture = unsafe { &mut *subobject.cast::<QueryFixture>() };
        fixture.calls += 1;
        fixture.result
    }

    unsafe extern "C" fn wrong_slot(_: *mut RootSlot190QuerySubobject) -> u32 {
        panic!("unexpected virtual slot")
    }

    #[test]
    fn zero_only_is_true_and_each_query_runs_once() {
        let mut vtable = [wrong_slot as RootSlot190QueryCallback; ROOT_SLOT_190_QUERY_SLOT + 1];
        vtable[ROOT_SLOT_190_QUERY_SLOT] = query;
        let mut fixture = QueryFixture { vtable: vtable.as_ptr(), result: 0, calls: 0 };
        let mut root = RootSlot190QueryRoot {
            unresolved_000_887: [0; ROOT_SLOT_190_SUBOBJECT_OFFSET / 4],
            query_subobject: (&mut fixture as *mut QueryFixture).cast(),
        };
        let receiver = RootQueryReceiver { opaque_00_27: [0xdead_beef; 10], root: &mut root };
        for (result, expected) in [(0, 1), (1, 0), (2, 0), (0x8000_0000, 0), (u32::MAX, 0), (0, 1)] {
            fixture.result = result;
            let before = fixture.calls;
            assert_eq!(unsafe { root_query_is_zero(&receiver) }, expected);
            assert_eq!(fixture.calls, before + 1);
            assert_eq!(fixture.result, result);
            assert_eq!(receiver.opaque_00_27, [0xdead_beef; 10]);
        }
    }
}
