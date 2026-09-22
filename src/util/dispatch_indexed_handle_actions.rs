//! `dispatch_indexed_handle_actions` — original: `FUN_082088ac` @
//! `0x082088ac` (72 bytes).
//! The next real function starts at `0x082088f4`. Raw A32 decoding finds three
//! inbound plain `bl` calls (`0x0821b7d8`, `0x0821b80c`, and `0x0821b85c`) and
//! no predicated inbound calls. Its body has two unconditional direct `bl`
//! calls (`indexed_slot_pointer` @ `0x0811f270` and the
//! `handle_deref_or_null` alias @ `0x083d61d0`) plus one unconditional indirect
//! `blx` through vtable slot +0x24; it contains no predicated calls.
//!
//! # Algorithm
//!
//! When `indexed_object` is non-null, iterate `indices[0..count]`. Each index
//! selects a handle slot from `indexed_object`; dereference its C++ handle and
//! invoke virtual slot 9 (+0x24) on the result. The incoming owner is saved by
//! the retail prologue but otherwise unused. Deviation: the two already-ported
//! direct callees are expressed as Rust calls; the virtual `blx` remains an
//! explicit target-width function-pointer call.

use crate::cxx::handle::handle_deref_or_null;
use crate::util::indexed_slot_pointer::indexed_slot_pointer;

type VirtualAction = unsafe extern "C" fn();

#[inline]
unsafe fn dispatch_indices<F: FnMut(u32)>(
    indexed_object: *const u32,
    indices: *const u32,
    count: u32,
    mut dispatch: F,
) {
    if indexed_object.is_null() {
        return;
    }
    for offset in 0..count as usize {
        dispatch(unsafe { indices.add(offset).read() });
    }
}

#[inline]
unsafe fn invoke_virtual_action(object: *mut u8) {
    let vtable = unsafe { object.cast::<u32>().read() as *const u32 };
    let action: VirtualAction = unsafe { core::mem::transmute(vtable.add(9).read() as usize) };
    unsafe { action() };
}

/// Dispatches virtual action slot +0x24 for every indexed handle selected by
/// `indices`.
///
/// # Safety
///
/// When `indexed_object` is non-null, `indices` must contain `count` readable
/// words. The object, its indexed table, every selected handle, and every
/// resolved object's vtable slot +0x24 must be valid exactly as required by
/// the retail code; null resolved handles fault during virtual dispatch.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dispatch_indexed_handle_actions(
    _owner: *mut u8,
    indices: *const u32,
    count: u32,
    indexed_object: *const u32,
) {
    unsafe {
        dispatch_indices(indexed_object, indices, count, |index| {
            let slot = indexed_slot_pointer(indexed_object, index);
            let object = handle_deref_or_null(slot.cast());
            invoke_virtual_action(object);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_indexed_object_does_not_read_indices() {
        unsafe {
            dispatch_indices(core::ptr::null(), core::ptr::null(), 3, |_| {
                panic!("null indexed object must skip dispatch")
            });
        }
    }

    #[test]
    fn zero_count_does_not_read_indices() {
        unsafe {
            dispatch_indices(1usize as *const u32, core::ptr::null(), 0, |_| {
                panic!("zero count must skip dispatch")
            });
        }
    }

    #[test]
    fn dispatches_each_index_once_in_input_order() {
        let indices = [17, 0, u32::MAX, 4];
        let mut dispatched = [0; 4];
        let mut count = 0;

        unsafe {
            dispatch_indices(1usize as *const u32, indices.as_ptr(), indices.len() as u32, |index| {
                dispatched[count] = index;
                count += 1;
            });
        }

        assert_eq!(count, indices.len());
        assert_eq!(dispatched, indices);
    }
}
