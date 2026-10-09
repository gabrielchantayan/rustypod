//! Descriptor duplicate lookup, `FUN_080daa7c` @ 0x080daa7c.
//!
//! True extent: 88 bytes, ending before the next prologue at 0x080daad4.
//! Raw ARM words verify two incoming plain BLs, zero predicated BLs, and
//! one outgoing plain BL at 0x080daab4 to 0x080615d4. If query byte +0x1d
//! has bit zero set, scan descriptor +0x24 via link +0x28. Return the first
//! link with the same owner word and a parent chain containing query.
//! No target behavioral deviations. The unported parent-chain predicate
//! retains its verified retail address; host builds execute its raw algorithm.

use core::ptr;

#[inline(always)]
unsafe fn has_query_parent(query: *mut u8, link: *mut u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let predicate: unsafe extern "C" fn(*mut u8, *mut u32) -> u32 =
            core::mem::transmute(0x0806_15d4usize);
        predicate(query, link)
    }
    #[cfg(not(target_os = "none"))]
    {
        if query.add(0x1d).read() & 1 == 0 { return 0; }
        let mut parent = link.add(1).read() as usize as *mut u32;
        while !parent.is_null() {
            if parent.cast::<u8>() == query { return 1; }
            parent = parent.add(1).read() as usize as *mut u32;
        }
        0
    }
}

/// # Safety
/// Query must be readable through byte +0x1d. On the flagged path descriptor
/// must contain word 9, and its finite list must contain readable words 0,
/// 1 and 10. Parent chains must be finite, readable target-width links.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn descriptor_find_duplicate(
    query: *mut u8, descriptor: *mut u32,
) -> *mut u32 {
    if query.add(0x1d).read() & 1 == 0 { return ptr::null_mut(); }
    let mut link = descriptor.add(9).read() as usize as *mut u32;
    while !link.is_null() {
        if link.read() == query.cast::<u32>().read() && has_query_parent(query, link) != 0 {
            return link;
        }
        link = link.add(10).read() as usize as *mut u32;
    }
    link
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_owner_ancestry_and_first_match() {
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::DESCRIPTOR_FIND_DUPLICATE, 0x1000,
        ).expect("32-bit descriptor links");
        unsafe {
            ptr::write_bytes(slab, 0, 0x1000);
            let query = slab;
            let descriptor = slab.add(0x80).cast::<u32>();
            let first = slab.add(0x100).cast::<u32>();
            let second = slab.add(0x180).cast::<u32>();
            let ancestor = slab.add(0x200).cast::<u32>();
            query.cast::<u32>().write(17);
            query.add(0x1d).write(0xfe);
            assert!(descriptor_find_duplicate(query, ptr::null_mut()).is_null());
            query.add(0x1d).write(0xff);
            assert!(descriptor_find_duplicate(query, descriptor).is_null());
            descriptor.add(9).write(first as usize as u32);
            first.write(18);
            // Mismatched owners must not dereference this invalid parent.
            first.add(1).write(1);
            first.add(10).write(second as usize as u32);
            second.write(17);
            assert!(descriptor_find_duplicate(query, descriptor).is_null());
            second.add(1).write(ancestor as usize as u32);
            ancestor.add(1).write(query as usize as u32);
            assert_eq!(descriptor_find_duplicate(query, descriptor), second);
            first.write(17);
            first.add(1).write(query as usize as u32);
            assert_eq!(descriptor_find_duplicate(query, descriptor), first);
            first.add(1).write(0);
            second.add(1).write(0);
            assert!(descriptor_find_duplicate(query, descriptor).is_null());
            // A candidate equal to query is not its own ancestor.
            descriptor.add(9).write(query as usize as u32);
            assert!(descriptor_find_duplicate(query, descriptor).is_null());
        }
    }
}
