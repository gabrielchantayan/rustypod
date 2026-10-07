//! Handler selection — `FUN_081623b0` @ 0x081623b0.
//!
//! Raw extent [0x081623b0,0x08162478): 200 bytes, two incoming plain BL
//! sites (0x081624c0,0x081626ac), no predicated incoming BL. The body has
//! nine plain BLs, no predicated BLs, and one virtual BLX at 0x08162438.
//! Try the nonzero identifier first; an implementation-bearing handle wins
//! without invoking its predicate. Otherwise scan handlers in order using
//! vtable slot 5 and copy-construct the first match, or the empty handle.
//! Release temporaries after copying. The vector count is recomputed after
//! each callback and its signed word-span result is compared as unsigned.
//! Deviations: repr(C) pointer fields widen on hosts; identifier lookup stays
//! a stock call to the raw-verified helper at 0x08162370, not a second port.
//! match.py: 63 Rust instructions versus 50 stock instructions; stock lookup
//! uses an absolute-address BLX, dereference/count helpers inline, while the
//! preference branch, slot-5 dispatch, live loop and handle cleanup remain.
use crate::cxx::handle::{RefcountedBody, refcounted_ptr_construct_slot1,
    refcounted_ptr_copy_assign_slot1, refcounted_ptr_copy_construct_slot1,
    refcounted_body_release_slot1};
use core::ptr;

#[repr(C)]
pub struct HandlerRegistry {
    pub vtable: usize,
    pub identifiers_begin: *const u32,
    pub identifiers_end: *const u32,
    pub identifiers_capacity: *const u32,
    pub handlers_begin: *mut *mut RefcountedBody,
    pub handlers_end: *mut *mut RefcountedBody,
    pub handlers_capacity: *mut *mut RefcountedBody,
}

type Lookup = unsafe extern "C" fn(*mut *mut RefcountedBody, *mut HandlerRegistry, u32);

/// # Safety
/// Registry vectors, handle bodies, implementation vtables and slot-5
/// predicates must be live; output must be writable uninitialized storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn handler_select(
    output: *mut *mut RefcountedBody, registry: *mut HandlerRegistry,
    query: u32, identifier: u32,
) {
    let lookup: Lookup = core::mem::transmute(0x0816_2370usize);
    select(output, registry, query, identifier, lookup);
}

unsafe fn select(output: *mut *mut RefcountedBody, registry: *mut HandlerRegistry,
    query: u32, identifier: u32, lookup: Lookup) {
    let mut preferred = ptr::null_mut();
    refcounted_ptr_construct_slot1(&mut preferred, 0, 0);
    if identifier != 0 {
        let mut found = ptr::null_mut();
        lookup(&mut found, registry, identifier);
        refcounted_ptr_copy_assign_slot1(&mut preferred, &found);
        refcounted_body_release_slot1(&mut found);
    }
    let mut selected = &preferred as *const *mut RefcountedBody;
    if preferred.is_null() || (*preferred).opaque0 == 0 {
        let mut index = 0u32;
        loop {
            let span = ((*registry).handlers_end as usize)
                .wrapping_sub((*registry).handlers_begin as usize) as isize;
            let count = (span >> core::mem::size_of::<usize>().trailing_zeros()) as u32;
            if index >= count { break; }
            let body = (*registry).handlers_begin.add(index as usize).read();
            let implementation = if body.is_null() { ptr::null_mut() }
                else { (*body).opaque0 as *mut u8 };
            let vtable = implementation.cast::<*const usize>().read();
            let accepts: unsafe extern "C" fn(*mut u8, u32) -> u32 =
                core::mem::transmute(vtable.add(5).read());
            if accepts(implementation, query) != 0 {
                selected = (*registry).handlers_begin.add(index as usize);
                break;
            }
            index = index.wrapping_add(1);
        }
    }
    refcounted_ptr_copy_construct_slot1(output, selected);
    refcounted_body_release_slot1(&mut preferred);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[repr(C)]
    struct Candidate { vtable: *const usize, key: u32, calls: u32 }
    unsafe extern "C" fn accepts(object: *mut u8, query: u32) -> u32 {
        let object = &mut *object.cast::<Candidate>();
        object.calls += 1;
        (object.key == query) as u32
    }
    unsafe extern "C" fn lookup(out: *mut *mut RefcountedBody,
        registry: *mut HandlerRegistry, id: u32) {
        let source = (*registry).handlers_begin.add((id - 1) as usize);
        refcounted_ptr_copy_construct_slot1(out, source);
    }
    #[test]
    fn preference_first_match_and_empty_result_preserve_ownership() {
        unsafe {
            let mut table = [0usize; 6]; table[5] = accepts as *const () as usize;
            let mut candidates = [Candidate { vtable: table.as_ptr(), key: 7, calls: 0 },
                Candidate { vtable: table.as_ptr(), key: 7, calls: 0 }];
            let mut bodies = [RefcountedBody { opaque0: ptr::addr_of_mut!(candidates[0]) as usize,
                refcount: 10, mutex: ptr::null_mut() },
                RefcountedBody { opaque0: ptr::addr_of_mut!(candidates[1]) as usize,
                refcount: 10, mutex: ptr::null_mut() }];
            let mut slots = [ptr::addr_of_mut!(bodies[0]), ptr::addr_of_mut!(bodies[1])];
            let mut registry = HandlerRegistry { vtable: 0, identifiers_begin: ptr::null(),
                identifiers_end: ptr::null(), identifiers_capacity: ptr::null(),
                handlers_begin: slots.as_mut_ptr(), handlers_end: slots.as_mut_ptr().add(2),
                handlers_capacity: slots.as_mut_ptr().add(2) };
            let mut out = ptr::null_mut();
            select(&mut out, &mut registry, 99, 2, lookup);
            assert_eq!(out, slots[1]); assert_eq!(bodies[1].refcount, 11);
            assert_eq!(candidates[0].calls + candidates[1].calls, 0);
            refcounted_body_release_slot1(&mut out);
            select(&mut out, &mut registry, 7, 0, lookup);
            assert_eq!(out, slots[0]); assert_eq!(candidates[0].calls, 1);
            assert_eq!(candidates[1].calls, 0);
            refcounted_body_release_slot1(&mut out);
            select(&mut out, &mut registry, 99, 0, lookup);
            assert!(out.is_null());
            assert_eq!((bodies[0].refcount, bodies[1].refcount), (10, 10));
            bodies[1].opaque0 = 0;
            select(&mut out, &mut registry, 7, 2, lookup);
            assert_eq!(out, slots[0]); assert_eq!(bodies[1].refcount, 10);
            refcounted_body_release_slot1(&mut out);
            registry.handlers_end = registry.handlers_begin;
            select(&mut out, &mut registry, 7, 0, lookup);
            assert!(out.is_null());
        }
    }
}
