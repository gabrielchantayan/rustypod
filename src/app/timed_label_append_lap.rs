//! Append a timed-label lap: `FUN_081d0f74` @ 0x081d0f74.
//!
//! Raw extent [0x081d0f74, 0x081d0fc4) is 80 bytes; the next function
//! begins with mov r1,#0 and clears owner fields. Two inbound plain BLs
//! (0x081d100c, 0x081d10ec), no predicated inbound BLs. Outbound: one
//! plain BL (operator_new), one predicated BLGT (collection removal), and
//! one virtual BLX. Allocate four bytes, copy the input word, submit its
//! pointer by reference through collection slot +0x1c at owner+0x30,
//! remove index zero if the signed append result exceeds 198, return 1.
//!
//! No target behavioral deviations; reuse the ported tag-2 allocator.
//! Collection removal at 0x083d2058 remains a firmware call, not a port.
//! Host vtable entries use native pointer width; owner+0x30 stays a byte
//! offset. Tests inject allocation/removal without changing global seams.

use crate::heap::veneers::operator_new;

type Append = unsafe extern "C" fn(*mut u8, *mut *mut u32) -> i32;
#[cfg(target_os = "none")]
type Remove = unsafe extern "C" fn(*mut u8, i32) -> i32;

unsafe fn remove_first(collection: *mut u8) {
    #[cfg(target_os = "none")]
    { core::mem::transmute::<usize, Remove>(0x083d_2058)(collection, 0); }
    #[cfg(not(target_os = "none"))]
    { let _ = collection; panic!("collection removal requires retailOS"); }
}

#[inline(always)]
unsafe fn append_with(
    owner: *mut u32, value: *const u32,
    allocate: impl FnOnce() -> *mut u32,
    remove: impl FnOnce(*mut u8),
) -> u32 {
    let mut cell = allocate();
    cell.write_volatile(value.read_volatile());
    let collection = owner.cast::<u8>().add(0x30);
    let vtable = collection.cast::<*const usize>().read();
    let append: Append = core::mem::transmute(vtable.add(7).read());
    if append(collection, &mut cell) > 198 {
        remove(collection);
    }
    1
}

/// # Safety
/// `owner+0x30` must be a live collection with a valid append vtable slot;
/// `value` must be a readable aligned word after allocation. Allocation
/// must succeed, and append must obey the collection's ownership contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timed_label_append_lap(owner: *mut u32, value: *const u32) -> u32 {
    append_with(owner, value, || operator_new(4).cast(), |collection| remove_first(collection))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Collection {
        vtable: *const usize,
        result: i32,
        observed: u32,
        appended: bool,
        removed: bool,
    }
    #[repr(C)]
    struct Owner { prefix: [u32; 12], collection: Collection }

    unsafe extern "C" fn append(collection: *mut u8, cell: *mut *mut u32) -> i32 {
        let collection = &mut *collection.cast::<Collection>();
        collection.observed = (*cell).read();
        collection.appended = true;
        // The callee may replace the local pointer; removal must not depend
        // on its value or on a successful append result.
        cell.write(core::ptr::null_mut());
        collection.result
    }

    #[test]
    fn copies_after_allocation_and_trims_only_above_signed_limit() {
        unsafe {
            let mut vtable = [0usize; 8];
            vtable[7] = append as *const () as usize;
            for result in [i32::MIN, -1, 0, 197, 198, 199, i32::MAX] {
                for input in [0, 1, u32::MAX] {
                    let mut owner = Owner {
                        prefix: [0xa5a5_a5a5; 12],
                        collection: Collection { vtable: vtable.as_ptr(), result,
                            observed: 0, appended: false, removed: false },
                    };
                    let mut value = input;
                    let value_ptr = &mut value as *mut u32;
                    let mut allocation = 0;
                    let status = append_with((&mut owner as *mut Owner).cast(), value_ptr,
                        || { value_ptr.write(input ^ 0x8000_0000); &mut allocation },
                        |collection| {
                            let collection = &mut *collection.cast::<Collection>();
                            assert!(collection.appended);
                            collection.removed = true;
                        });
                    assert_eq!(status, 1);
                    assert_eq!(allocation, input ^ 0x8000_0000);
                    assert_eq!(owner.collection.observed, allocation);
                    assert!(owner.collection.appended);
                    assert_eq!(owner.collection.removed, result > 198);
                    assert_eq!(owner.prefix, [0xa5a5_a5a5; 12]);
                }
            }
        }
    }
}
