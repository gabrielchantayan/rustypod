//! Dispatch payload-vector members — `FUN_0811f150` @ `0x0811f150`.
//!
//! True size 84 bytes: return at 0x0811f1a0, next prologue 0x0811f1a4.
//! Raw words verify two inbound plain BLs, three outbound plain BLs (two
//! handle_deref_or_null aliases, one vector_size_elem4), no predicated BLs,
//! and one virtual BLX. Iterate unsigned indices, skip null handle payloads,
//! dereference nonnull handles again, then call vtable slot 0x24 with this.
//! Reload bounds each iteration so callbacks may resize or replace storage.
//! Deliberate deviations: host pointers/vtable entries use native width and
//! host counts divide by native slot width. No identity is assumed for slot 9.

use crate::cxx::handle::handle_deref_or_null;
use crate::cxx::templates::VectorBounds;
#[cfg(target_os = "none")]
use crate::cxx::templates::vector_size_elem4;

#[repr(C)]
pub struct PayloadVector {
    pub prefix: u32,
    pub vector: VectorBounds,
}

type Dispatch = unsafe extern "C" fn(*mut u8);

#[inline(always)]
unsafe fn vector_begin(vector: *const VectorBounds) -> *mut u8 {
    #[cfg(target_os = "none")]
    { core::ptr::addr_of!((*vector).begin).read() }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of!((*vector).begin).read_unaligned() }
}

/// # Safety
/// The owner and vector slots must be readable. Each nonnull cell contains
/// either null or an object with a valid vtable slot 9 accepting this in r0.
/// Callbacks must preserve the owner and subsequent readable vector storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn payload_vector_dispatch(owner: *mut PayloadVector) {
    let vector = core::ptr::addr_of!((*owner).vector);
    let mut index = 0u32;
    loop {
        #[cfg(target_os = "none")]
        let count = vector_size_elem4(vector) as u32;
        #[cfg(not(target_os = "none"))]
        let count = {
            let begin = core::ptr::addr_of!((*vector).begin).read_unaligned() as usize;
            let end = core::ptr::addr_of!((*vector).end).read_unaligned() as usize;
            ((end.wrapping_sub(begin) as isize) >> core::mem::size_of::<usize>().trailing_zeros()) as u32
        };
        if index >= count { return; }
        let begin = vector_begin(vector);
        let slot = begin.cast::<*const *mut u8>().add(index as usize);
        if !handle_deref_or_null(slot).is_null() {
            let begin = vector_begin(vector);
            let object = handle_deref_or_null(begin.cast::<*const *mut u8>().add(index as usize));
            let vtable = object.cast::<*const usize>().read();
            let dispatch: Dispatch = core::mem::transmute(vtable.add(9).read());
            dispatch(object);
        }
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[repr(C)]
    struct Object { vtable: *const usize, visits: u32, owner: *mut PayloadVector, replacement: *mut u8, end: *mut u8 }
    unsafe extern "C" fn visit(object: *mut u8) {
        let object = &mut *object.cast::<Object>();
        object.visits += 1;
        if !object.owner.is_null() {
            (*object.owner).vector.begin = object.replacement;
            (*object.owner).vector.end = object.end;
        }
    }
    #[test]
    fn empty_null_cells_order_and_callback_replacement() {
        unsafe {
            let mut table = [0usize; 10];
            table[9] = visit as *const () as usize;
            let mut first = Object { vtable: table.as_ptr(), visits: 0, owner: core::ptr::null_mut(), replacement: core::ptr::null_mut(), end: core::ptr::null_mut() };
            let mut second = Object { vtable: table.as_ptr(), visits: 0, owner: core::ptr::null_mut(), replacement: core::ptr::null_mut(), end: core::ptr::null_mut() };
            let mut first_cell = (&mut first as *mut Object).cast::<u8>();
            let mut second_cell = (&mut second as *mut Object).cast::<u8>();
            let mut null_cell = core::ptr::null_mut::<u8>();
            let mut slots = [core::ptr::null_mut(), &mut null_cell, &mut first_cell, &mut second_cell];
            let begin = slots.as_mut_ptr().cast::<u8>();
            let mut owner = PayloadVector { prefix: 77, vector: VectorBounds { begin, end: begin } };
            payload_vector_dispatch(&mut owner);
            assert_eq!((first.visits, second.visits), (0, 0));
            owner.vector.end = slots.as_mut_ptr().add(4).cast();
            payload_vector_dispatch(&mut owner);
            assert_eq!((first.visits, second.visits), (1, 1));
            // Replacing storage must change the slot visited at index 3.
            let mut replacement = [core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), &mut first_cell];
            first.owner = &mut owner;
            first.replacement = replacement.as_mut_ptr().cast();
            first.end = replacement.as_mut_ptr().add(4).cast();
            payload_vector_dispatch(&mut owner);
            assert_eq!((first.visits, second.visits), (3, 1));
            // Shrinking to empty in the callback stops before index 3.
            owner.vector = VectorBounds { begin, end: slots.as_mut_ptr().add(4).cast() };
            first.end = first.replacement;
            payload_vector_dispatch(&mut owner);
            assert_eq!((first.visits, second.visits), (4, 1));
            assert_eq!(owner.prefix, 77);
        }
    }
}
