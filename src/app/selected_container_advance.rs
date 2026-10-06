//! Selected container advance — FUN_0815aa84 @ 0x0815aa84.
//! True extent: 116 bytes through 0x0815aaf7, including the literal at
//! 0x0815aaf4; the next independent prologue starts at 0x0815aaf8.
//! Raw decoding: three internal unconditional BL, zero predicated BL,
//! one virtual BLX and a tail B to 0x081bb29c. Two inbound plain BL
//! (0x081f6194, 0x081f61bc), zero predicated inbound BL.
//! If the deque at owner+0xa0 is nonempty, take its back object, increment
//! its u16 index and sign-extend the wrapped result. Reject it when the
//! signed item count minus one is smaller. Otherwise store the index,
//! dispatch vtable slot +0x58 with event 0x424d6170 and owner word +0x60,
//! then invoke singleton_class_8c00_ready_gate with one.
//! Deliberate deviations: reuse existing container/deque/count Rust ports;
//! the identified but unported ready gate remains a retail call on ARM and
//! an explicitly installed callback on hosts. No NULL guards are added.

use crate::cxx::container_item_count_or_zero::container_item_count_or_zero;
use crate::cxx::templates::{container_is_empty, deque_back_elem4};

type ReadyGate = unsafe extern "C" fn(u32);
type Dispatch = unsafe extern "C" fn(*mut u8, u32, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_ready_gate(_: u32) {
    panic!("install selected-container ready gate before advancing")
}
#[cfg(not(target_os = "none"))]
pub static mut SELECTED_CONTAINER_READY_GATE: ReadyGate = missing_ready_gate;

/// # Safety
/// Owner must expose the target-layout deque at +0xa0, context word at +0x60,
/// and a valid vtable with a callable +0x58 slot. The back object must have
/// a writable index and valid embedded container/count for the count port.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selected_container_advance(owner: *mut u8) {
    advance_with(owner,
        |deque| container_is_empty(deque),
        |deque| deque_back_elem4(deque.cast()).cast::<*mut u8>().read(),
        |object| container_item_count_or_zero(object),
        |owner| {
            let vtable = owner.cast::<*const u8>().read();
            let dispatch: Dispatch = core::mem::transmute(vtable.add(0x58).cast::<usize>().read());
            dispatch(owner, 0x424d_6170, owner.add(0x60).cast::<u32>().read());
        },
        || {
            #[cfg(target_os = "none")]
            let ready: ReadyGate = core::mem::transmute(0x081b_b29cusize);
            #[cfg(not(target_os = "none"))]
            let ready = core::ptr::addr_of!(SELECTED_CONTAINER_READY_GATE).read_volatile();
            ready(1);
        });
}

unsafe fn advance_with(
    owner: *mut u8,
    mut empty: impl FnMut(*const u8) -> u32,
    mut back: impl FnMut(*const u8) -> *mut u8,
    mut count: impl FnMut(*const u8) -> i32,
    mut dispatch: impl FnMut(*mut u8),
    mut ready: impl FnMut(),
) {
    let deque = owner.add(0xa0);
    if empty(deque) != 0 { return; }
    let object = back(deque);
    let next = object.cast::<u16>().read().wrapping_add(1) as i16;
    if count(object).wrapping_sub(1) < next as i32 { return; }
    object.cast::<i16>().write(next);
    dispatch(owner);
    ready();
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn empty_owner_never_reads_back_or_dispatches() {
        let mut owner = [0u32; 60];
        unsafe { selected_container_advance(owner.as_mut_ptr().cast()); }
    }

    #[test]
    fn signed_wrap_bounds_and_store_before_dispatch() {
        for (index, count, expected) in [
            (0u16, 1i16, None), (0, 2, Some(1i16)),
            (1, 2, None), (32766, 32767, None),
            (32767, 0, Some(-32768)), (65535, 0, None),
            (65535, 1, Some(0)), (65534, 0, Some(-1)),
        ] {
            let mut owner = [0u32; 60];
            let mut object = [0u32; 10];
            object[0] = index as u32;
            object[9] = count as u16 as u32;
            // Embedded count at object+4+0x20: nonzero selects signed count.
            if count == 0 { object[9] = 0; }
            let stage = Cell::new(0);
            unsafe {
                let object_ptr = object.as_mut_ptr().cast::<u8>();
                advance_with(owner.as_mut_ptr().cast(), |_| 0, |_| object_ptr,
                    |p| container_item_count_or_zero(p),
                    |_| {
                        assert_eq!(object_ptr.cast::<i16>().read(), expected.unwrap());
                        assert_eq!(stage.replace(1), 0);
                    },
                    || { assert_eq!(stage.replace(2), 1); });
            }
            assert_eq!(stage.get(), if expected.is_some() { 2 } else { 0 });
            assert_eq!(object[0] as u16, expected.map(|x| x as u16).unwrap_or(index));
        }
    }
}
