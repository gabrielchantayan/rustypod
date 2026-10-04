//! `context_range_release` — `FUN_081f0dcc` at 0x081f0dcc, 172 bytes,
//! [0x081f0dcc,0x081f0e78); the next independently entered body starts there.
//! Raw A32 decoding: two plain outbound BLs, one predicated outbound BL,
//! one indirect BLX; zero plain and two predicated inbound BLs.
//!
//! Query the associated object's vtable slot +0x0c for inclusive bounds,
//! intersect them with the signed requested range, and visit each index.
//! For a present flagged payload, invalidate its indexed record, then reload
//! the node pointer and remove it from the context's +0x14 tree only if its
//! +0x40 word is zero. Bounds of -1 disable traversal. Increment wraps just
//! as ADD does (an upper bound of INT_MAX can therefore cause nontermination).
//! No target behavioral deviations. The input r3 seeds the lower-bound output
//! before virtual dispatch. Unported invalidation and removal remain calls to
//! verified firmware addresses; host-only seams widen payload pointer slots.
//! The removal wrapper's incoming r2/r3 are irrelevant: its helper overwrites
//! the stack output copied from r3 without reading its initial value.

#[repr(C)]
pub struct RangeReleaseContext {
    pub prefix: [u32; 12],
    pub associated: *mut u8,
}

pub type PayloadLookup = unsafe extern "C" fn(*mut u8, u32) -> *mut u8;
pub type RecordInvalidate = unsafe extern "C" fn(*mut u8, u32);
pub type TreeNodeRemove = unsafe extern "C" fn(*mut u8, *const *mut u8, usize, usize);
type QueryBounds = unsafe extern "C" fn(*mut u8, *mut i32, *mut i32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lookup(_: *mut u8, _: u32) -> *mut u8 {
    panic!("install range release payload lookup host seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_invalidate(_: *mut u8, _: u32) {
    panic!("install range release record invalidation host seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_remove(_: *mut u8, _: *const *mut u8, _: usize, _: usize) {
    panic!("install range release tree removal host seam")
}
#[cfg(not(target_os = "none"))]
pub static mut RANGE_RELEASE_LOOKUP: PayloadLookup = missing_lookup;
#[cfg(not(target_os = "none"))]
pub static mut RANGE_RELEASE_INVALIDATE: RecordInvalidate = missing_invalidate;
#[cfg(not(target_os = "none"))]
pub static mut RANGE_RELEASE_REMOVE: TreeNodeRemove = missing_remove;

/// # Safety
/// The context, associated object, virtual bounds method and selected payloads
/// must satisfy the firmware contracts. Nodes must be readable at +0x40 and
/// belong to the embedded tree. Host seams must be installed without races.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_range_release(
    context: *mut RangeReleaseContext, mut first: i32, mut last: i32, lower_seed: i32,
) {
    let associated = (*context).associated;
    let vtable = associated.cast::<*const usize>().read();
    let bounds: QueryBounds = core::mem::transmute(vtable.add(3).read());
    let mut lower = lower_seed;
    let mut upper = last;
    bounds(associated, &mut lower, &mut upper);
    if lower == -1 || upper == -1 || first > upper { return; }
    if first < lower { first = lower; }
    if last < lower { return; }
    if last > upper { last = upper; }
    while first <= last {
        #[cfg(target_os = "none")]
        let lookup: PayloadLookup = crate::cxx::vtable_slot_10_flagged_payload::vtable_slot_10_flagged_payload;
        #[cfg(not(target_os = "none"))]
        let lookup = core::ptr::addr_of!(RANGE_RELEASE_LOOKUP).read_volatile();
        let payload = lookup((*context).associated, first as u32);
        if !payload.is_null() {
            #[cfg(target_os = "none")]
            let invalidate: RecordInvalidate = core::mem::transmute(0x081f_d008usize);
            #[cfg(not(target_os = "none"))]
            let invalidate = core::ptr::addr_of!(RANGE_RELEASE_INVALIDATE).read_volatile();
            invalidate((*context).associated, first as u32);
            let node = payload.cast::<*mut u8>().read();
            if node.add(0x40).cast::<u32>().read() == 0 {
                #[cfg(target_os = "none")]
                let remove: TreeNodeRemove = core::mem::transmute(0x083d_bc44usize);
                #[cfg(not(target_os = "none"))]
                let remove = core::ptr::addr_of!(RANGE_RELEASE_REMOVE).read_volatile();
                remove(context.cast::<u8>().add(0x14), &node, 0, 0);
            }
        }
        first = first.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());

    #[repr(C)]
    struct Object {
        vtable: *const usize,
        lower: i32,
        upper: i32,
        seen_seed: i32,
        visits: Vec<i32>,
        invalidated: Vec<i32>,
        slot: *mut u8,
        node: [u32; 17],
        replacement: [u32; 17],
        replace: bool,
    }
    unsafe extern "C" fn bounds(object: *mut u8, lower: *mut i32, upper: *mut i32) {
        let object = &mut *object.cast::<Object>();
        object.seen_seed = *lower;
        *lower = object.lower;
        *upper = object.upper;
    }
    unsafe extern "C" fn lookup(object: *mut u8, index: u32) -> *mut u8 {
        let object = &mut *object.cast::<Object>();
        object.visits.push(index as i32);
        if index as i32 == 0 { return core::ptr::null_mut(); }
        object.node[16] = if index as i32 == 2 { 1 } else { 0 };
        object.slot = object.node.as_mut_ptr().cast();
        core::ptr::addr_of_mut!(object.slot).cast()
    }
    unsafe extern "C" fn invalidate(object: *mut u8, index: u32) {
        let object = &mut *object.cast::<Object>();
        object.invalidated.push(index as i32);
        if object.replace { object.slot = object.replacement.as_mut_ptr().cast(); }
    }
    unsafe extern "C" fn remove(tree: *mut u8, slot: *const *mut u8, _: usize, _: usize) {
        // Simulate a visible tree count mutation, independent of callback logs.
        let count = tree.cast::<u32>();
        count.write(count.read() + 1);
        (*slot).cast::<u32>().write(0xfeed);
    }
    struct Restore(PayloadLookup, RecordInvalidate, TreeNodeRemove);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            RANGE_RELEASE_LOOKUP = self.0;
            RANGE_RELEASE_INVALIDATE = self.1;
            RANGE_RELEASE_REMOVE = self.2;
        } }
    }
    #[test]
    fn signed_intersections_missing_payloads_and_node_retention() {
        let _lock = LOCK.lock();
        let _restore = unsafe {
            let old = Restore(RANGE_RELEASE_LOOKUP, RANGE_RELEASE_INVALIDATE, RANGE_RELEASE_REMOVE);
            RANGE_RELEASE_LOOKUP = lookup;
            RANGE_RELEASE_INVALIDATE = invalidate;
            RANGE_RELEASE_REMOVE = remove;
            old
        };
        let vtable = [0, 0, 0, bounds as usize];
        for (lower, upper) in [(-1, 3), (0, -1), (-3, 3), (1, 3), (3, 1)] {
            for first in -4..=4 {
                for last in -4..=4 {
                    let mut object = Object { vtable: vtable.as_ptr(), lower, upper,
                        seen_seed: 0, visits: Vec::new(), invalidated: Vec::new(),
                        slot: core::ptr::null_mut(), node: [0; 17], replacement: [0; 17], replace: false };
                    let mut context = RangeReleaseContext { prefix: [0; 12], associated: (&mut object as *mut Object).cast() };
                    unsafe { context_range_release(&mut context, first, last, 73); }
                    let expected: Vec<i32> = (first..=last).filter(|i|
                        lower != -1 && upper != -1 && *i >= lower && *i <= upper).collect();
                    let present: Vec<i32> = expected.iter().copied().filter(|i| *i != 0).collect();
                    assert_eq!(object.visits, expected);
                    assert_eq!(object.invalidated, present);
                    assert_eq!(context.prefix[5], present.iter().filter(|i| **i != 2).count() as u32);
                    assert_eq!(object.seen_seed, 73);
                }
            }
        }
        // Invalidation can replace the payload's node. Inspect the replacement,
        // not a node cached before the invalidation call.
        let mut object = Object { vtable: vtable.as_ptr(), lower: 2, upper: 2,
            seen_seed: 0, visits: Vec::new(), invalidated: Vec::new(),
            slot: core::ptr::null_mut(), node: [0; 17], replacement: [0; 17], replace: true };
        let mut context = RangeReleaseContext { prefix: [0; 12], associated: (&mut object as *mut Object).cast() };
        unsafe { context_range_release(&mut context, 2, 2, -1); }
        assert_eq!(context.prefix[5], 1);
        assert_eq!(object.replacement[0], 0xfeed);
        assert_eq!(object.node[0], 0);
    }
}
