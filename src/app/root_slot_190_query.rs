//! Root pending-work query veneer.
//!
//! `root_slot_190_query` — original: `FUN_081115e4` @ **0x081115e4**
//! (**16 bytes**, `0x081115e4..0x081115f4`; the distinct following function
//! begins `push {r4, lr}` / `e92d4010` at 0x081115f4). Raw-image decoding
//! finds exactly **six direct `bl` call sites**, all unconditional:
//! `0x08112bc4`, `0x081147b0`, `0x081161b0`, `0x0812f34c`, `0x082199ec`, and
//! `0x08289a48`; there are no predicated or direct-`b` callers and no aligned
//! data word references. Ghidra incorrectly gives this a `void` result and
//! drops its argument.
//!
//! # Algorithm
//!
//! Load the root's pending-work sub-object from `+0x888`, load its vtable, and
//! tail-call word slot 100 (`+0x190`) with that sub-object as `r0`. The
//! callback's `u32` result passes through unchanged.
//!
//! # Deliberate deviations
//!
//! The ARM vtable is word-addressed; its host representation is an array of
//! native-width callback pointers indexed by the same word slot. Rust emits a
//! normal indirect call rather than ARM's `bx`, preserving the ABI-visible
//! argument and return value.

/// ARMv5TE byte offset of the root pointer to its pending-work sub-object.
pub const ROOT_SLOT_190_SUBOBJECT_OFFSET: usize = 0x888;
/// ARMv5TE word index for the pending-work query vtable slot at `+0x190`.
pub const ROOT_SLOT_190_QUERY_SLOT: usize = 0x190 / 4;

/// ABI of the pending-work query virtual callback.
pub type RootSlot190QueryCallback = unsafe extern "C" fn(*mut RootSlot190QuerySubobject) -> u32;

/// Root prefix consumed by [`root_slot_190_query`].
///
/// `query_subobject` is at `+0x888` on the ARM target. Native host pointer
/// width is intentional so host fixtures can carry callable pointers.
#[repr(C)]
pub struct RootSlot190QueryRoot {
    pub unresolved_000_887: [u32; ROOT_SLOT_190_SUBOBJECT_OFFSET / 4],
    pub query_subobject: *mut RootSlot190QuerySubobject,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; ROOT_SLOT_190_SUBOBJECT_OFFSET] =
    [0; core::mem::offset_of!(RootSlot190QueryRoot, query_subobject)];

/// The `+0x888` root sub-object prefix consumed by the query callback.
#[repr(C)]
pub struct RootSlot190QuerySubobject {
    pub vtable: *const RootSlot190QueryCallback,
}

/// Calls the root pending-work query at vtable slot `+0x190`.
///
/// # Safety
///
/// `root`, its `+0x888` sub-object, and the sub-object vtable's slot `+0x190`
/// must be valid. The stock veneer performs no NULL checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.root_slot_190_query")]
pub unsafe extern "C" fn root_slot_190_query(root: *mut RootSlot190QueryRoot) -> u32 {
    let subobject = unsafe { (*root).query_subobject };
    let callback = unsafe { (*subobject).vtable.add(ROOT_SLOT_190_QUERY_SLOT).read() };
    unsafe { callback(subobject) }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[repr(C)]
    struct QueryFixture {
        vtable: *const RootSlot190QueryCallback,
        result: u32,
    }

    unsafe extern "C" fn wrong_slot(_subobject: *mut RootSlot190QuerySubobject) -> u32 {
        0xdead_beef
    }

    unsafe extern "C" fn fixture_result(subobject: *mut RootSlot190QuerySubobject) -> u32 {
        unsafe { (*subobject.cast::<QueryFixture>()).result }
    }

    #[test]
    fn forwards_the_subobject_to_slot_190_and_preserves_its_result() {
        for result in [0, u32::MAX] {
            let mut vtable = [wrong_slot as RootSlot190QueryCallback; ROOT_SLOT_190_QUERY_SLOT + 1];
            vtable[ROOT_SLOT_190_QUERY_SLOT] = fixture_result;
            let mut query_subobject = QueryFixture { vtable: vtable.as_ptr(), result };
            let mut root = RootSlot190QueryRoot {
                unresolved_000_887: [0; ROOT_SLOT_190_SUBOBJECT_OFFSET / 4],
                query_subobject: (&mut query_subobject as *mut QueryFixture).cast(),
            };

            assert_eq!(unsafe { root_slot_190_query(&mut root) }, result);
        }
    }
}
