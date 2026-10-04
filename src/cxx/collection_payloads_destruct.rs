//! Collection payload destructor — `FUN_0821025c` @ **0x0821025c**.
//!
//! Raw A32 extent: **80 bytes**, ending before the next function at
//! `0x082102ac`. Five plain BL instructions, zero predicated BL instructions;
//! whole-image decoding finds two inbound plain BL sites and no predicated
//! BL sites (0x08119d94 and 0x081b1f08).
//!
//! Walk the collection using its existing cursor, free each item's +0x2c
//! payload with heap tag 27 (including NULL), invalidate the cursor, then
//! run the attached-release cleanup destructor. Payload words are not cleared.
//! Deliberate deviations: omit Ghidra's spurious r1-r3 parameters (saved
//! registers, not inputs); use the existing Rust cursor and heap ports.
//! Return the final destructor's object pointer, as the original preserves r0.
//! ARM match review: LLVM removes the dead stack-local cursor invalidation
//! and duplicates the initial advance before the loop. The +0x2c load, tag
//! 27, nonzero loop condition and final destructor call remain intact.

use crate::util::cursor::{Collection, Cursor, cursor_init, cursor_advance, cursor_invalidate};

unsafe fn release_payloads(collection: *mut Collection, mut release: impl FnMut(*mut u8, u32)) {
    let mut cursor = Cursor { collection: core::ptr::null_mut(), index: 0 };
    let mut item: *mut u32 = core::ptr::null_mut();
    unsafe {
        cursor_init(&mut cursor, collection);
        while cursor_advance(&mut cursor, core::ptr::addr_of_mut!(item).cast()) != 0 {
            release(item.add(11).read() as usize as *mut u8, 27);
        }
        cursor_invalidate(&mut cursor);
    }
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn collection_payloads_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        release_payloads(this.cast(), |payload, tag| crate::heap::veneers::free_wrapper(payload, tag as usize));
        crate::cxx::observable_array_attached_release_cleanup_destruct::observable_array_attached_release_cleanup_destruct(this)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::util::cursor::CollectionVtable;
    use std::vec::Vec;

    #[repr(C)]
    struct Fixture {
        collection: Collection,
        items: [[u32; 12]; 3],
        count: usize,
        indices: Vec<i32>,
    }

    unsafe extern "C" fn item_at(collection: *mut Collection, index: i32, out: *mut u8) -> u32 {
        let fixture = unsafe { &mut *collection.cast::<Fixture>() };
        fixture.indices.push(index);
        if index < 0 || index as usize >= fixture.count { return 0; }
        unsafe { out.cast::<*mut u32>().write(fixture.items[index as usize].as_mut_ptr()); }
        7 // Any nonzero accessor result means success, not just 1.
    }

    #[test]
    fn walks_empty_and_multiple_items_without_clearing_payloads() {
        let vtable = CollectionVtable { unresolved: [0; 15], item_at };
        for count in [0, 1, 3] {
            let mut fixture = Fixture {
                collection: Collection { vtable: &vtable },
                items: [[0xfeed_face; 12]; 3], count, indices: Vec::new(),
            };
            fixture.items[0][11] = 0x1234;
            fixture.items[1][11] = 0;
            fixture.items[2][11] = 0xffff_fffc;
            let original = fixture.items;
            let mut released = Vec::new();
            unsafe { release_payloads(&mut fixture.collection, |payload, tag| released.push((payload as usize, tag))); }
            let expected: Vec<_> = original[..count].iter().map(|item| (item[11] as usize, 27)).collect();
            assert_eq!(released, expected);
            assert_eq!(fixture.indices, (0..=count as i32).collect::<Vec<_>>());
            assert_eq!(fixture.items, original);
        }
    }
}
