//! Selected container retreat — FUN_0815a99c @ 0x0815a99c.
//! True extent: 100 bytes, including event literal at 0x0815a9fc;
//! the next independent prologue starts at 0x0815aa00.
//! Two outbound plain BL, zero predicated BL, one virtual BLX, and a
//! tail B to 0x081bb29c. Two inbound plain BL (0x081f60f4, 0x081f61a4),
//! zero predicated inbound BL, verified by whole-image aligned decoding.
//! For a nonempty deque at owner+0xa0, decrement its back object's u16
//! index with wrapping, sign-extend to i16, and reject negative results.
//! Store accepted indices before dispatching event 0x424d6170 through
//! vtable slot +0x58 with owner word +0x60, then invoke the ready gate(1).
//! Deliberate deviations: reuse existing Rust empty/back ports and the
//! adjacent advance port's host ready-gate seam; the identified unported
//! ready gate remains a retail call on ARM. No additional NULL guards.

use crate::cxx::templates::{container_is_empty, deque_back_elem4};

type Dispatch = unsafe extern "C" fn(*mut u8, u32, u32);
type ReadyGate = unsafe extern "C" fn(u32);

/// # Safety
/// Owner must contain the deque at +0xa0, context word at +0x60, and a
/// valid vtable with callable +0x58 slot. Its back element must point to
/// an object with a writable aligned u16 index at offset zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selected_container_retreat(owner: *mut u8) {
    retreat_with(owner,
        |deque| container_is_empty(deque),
        |deque| deque_back_elem4(deque.cast()).cast::<*mut u8>().read(),
        |owner| {
            let vtable = owner.cast::<*const u8>().read();
            let dispatch: Dispatch = core::mem::transmute(vtable.add(0x58).cast::<usize>().read());
            dispatch(owner, 0x424d_6170, owner.add(0x60).cast::<u32>().read());
        },
        || {
            #[cfg(target_os = "none")]
            let ready: ReadyGate = core::mem::transmute(0x081b_b29cusize);
            #[cfg(not(target_os = "none"))]
            let ready: ReadyGate = core::ptr::addr_of!(
                crate::app::selected_container_advance::SELECTED_CONTAINER_READY_GATE
            ).read_volatile();
            ready(1);
        });
}

unsafe fn retreat_with(
    owner: *mut u8,
    mut empty: impl FnMut(*const u8) -> u32,
    mut back: impl FnMut(*const u8) -> *mut u8,
    mut dispatch: impl FnMut(*mut u8),
    mut ready: impl FnMut(),
) {
    let deque = owner.add(0xa0);
    if empty(deque) != 0 { return; }
    let object = back(deque);
    let previous = object.cast::<u16>().read().wrapping_sub(1) as i16;
    if previous < 0 { return; }
    object.cast::<i16>().write(previous);
    dispatch(owner);
    ready();
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn empty_deque_does_not_access_object_or_dispatch() {
        let mut owner = [0u32; 60];
        unsafe {
            retreat_with(owner.as_mut_ptr().cast(), |_| 7,
                |_| panic!("empty deque read"), |_| panic!("empty dispatch"),
                || panic!("empty ready gate"));
        }
    }

    #[test]
    fn wrapped_signed_boundary_and_store_before_dispatch() {
        for index in [0u16, 1, 2, 32767, 32768, 32769, 65534, 65535] {
            let expected = index.wrapping_sub(1);
            let accepted = expected & 0x8000 == 0;
            let mut owner = [0u32; 60];
            let mut object = [index, 0xbeef];
            let stage = Cell::new(0);
            unsafe {
                let object_ptr = object.as_mut_ptr().cast::<u8>();
                retreat_with(owner.as_mut_ptr().cast(), |_| 0, |_| object_ptr,
                    |_| {
                        assert_eq!(object_ptr.cast::<u16>().read(), expected);
                        assert_eq!(stage.replace(1), 0);
                    },
                    || { assert_eq!(stage.replace(2), 1); });
            }
            assert_eq!(stage.get(), if accepted { 2 } else { 0 });
            assert_eq!(object, [if accepted { expected } else { index }, 0xbeef]);
        }
    }
}
