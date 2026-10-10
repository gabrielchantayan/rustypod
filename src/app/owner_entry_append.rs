//! Append an entry to its owner's doubly linked list.
//!
//! retailOS 0x0807f564, 60 bytes [0x0807f564,0x0807f5a0).
//! Raw A32: two inbound plain BLs (0x0805e660,0x0806a788), zero
//! predicated inbound BLs, zero outbound BLs, one tail B to 0x080e2d28.
//! Clear next, capture the old tail as previous, update head or old tail's
//! next, publish the new tail, increment count modulo 2^32, then dispatch
//! the verified retail helper. Its identity is not inferred from Ghidra.
//! Deviations: repr(C) native pointers widen on hosts; target field offsets
//! remain +0/+4/+8 for entries and +0x24/+0x28/+0x2c for owners. The tail
//! branch is a Rust call; the unported helper uses a host callback seam.

#[repr(C)]
pub struct OwnerEntry {
    pub owner: *mut EntryOwner,
    pub next: *mut OwnerEntry,
    pub previous: *mut OwnerEntry,
}

#[repr(C)]
pub struct EntryOwner {
    pub reserved: [u32; 9],
    pub count: u32,
    pub head: *mut OwnerEntry,
    pub tail: *mut OwnerEntry,
}

type TailHelper = unsafe extern "C" fn(*mut EntryOwner);
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_tail_helper(_: *mut EntryOwner) {
    panic!("retail helper 0x080e2d28 unavailable on host")
}
#[cfg(not(target_os = "none"))]
pub static mut OWNER_ENTRY_TAIL_HELPER: TailHelper = missing_tail_helper;

/// # Safety
/// Entry, its owner, and any nonnull old tail must be live writable objects.
/// Entry must not already belong to the list. On target, the owner must also
/// satisfy retail helper 0x080e2d28's contract (including its +0x900 field).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_entry_append(entry: *mut OwnerEntry) {
    let owner = (*entry).owner;
    (*entry).next = core::ptr::null_mut();
    (*entry).previous = (*owner).tail;
    let tail = (*owner).tail;
    if tail.is_null() {
        (*owner).head = entry;
    } else {
        (*tail).next = entry;
    }
    (*owner).tail = entry;
    (*owner).count = (*owner).count.wrapping_add(1);
    #[cfg(target_os = "none")]
    {
        let helper: TailHelper = core::mem::transmute(0x080e2d28usize);
        helper(owner);
    }
    #[cfg(not(target_os = "none"))]
    { (core::ptr::read_volatile(core::ptr::addr_of!(OWNER_ENTRY_TAIL_HELPER)))(owner); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    unsafe extern "C" fn inspect_published_list(owner: *mut EntryOwner) {
        let mut current = (*owner).head;
        let mut previous = ptr::null_mut();
        while !current.is_null() {
            assert_eq!((*current).owner, owner);
            assert_eq!((*current).previous, previous);
            previous = current;
            current = (*current).next;
        }
        assert_eq!(previous, (*owner).tail);
        // Mutating count proves dispatch happens after the increment, not before.
        (*owner).reserved[0] = (*owner).count;
        (*owner).count ^= 0x80000000;
    }

    #[test]
    fn empty_then_nonempty_preserves_links_and_wraps_count_before_dispatch() {
        unsafe {
            OWNER_ENTRY_TAIL_HELPER = inspect_published_list;
            for initial in [0, 7, u32::MAX] {
                let mut owner = EntryOwner { reserved: [0x12345678; 9], count: initial,
                    head: ptr::null_mut(), tail: ptr::null_mut() };
                let mut entries = core::array::from_fn::<_, 3, _>(|_| OwnerEntry {
                    owner: &mut owner, next: ptr::dangling_mut(), previous: ptr::dangling_mut(),
                });
                let mut expected = initial;
                for i in 0..entries.len() {
                    owner_entry_append(&mut entries[i]);
                    expected = expected.wrapping_add(1);
                    assert_eq!(owner.reserved[0], expected);
                    expected ^= 0x80000000;
                    assert_eq!(owner.count, expected);
                    assert_eq!(owner.head, &mut entries[0] as *mut _);
                    assert_eq!(owner.tail, &mut entries[i] as *mut _);
                    assert!(entries[i].next.is_null());
                    assert_eq!(&owner.reserved[1..], &[0x12345678; 8]);
                }
            }
            OWNER_ENTRY_TAIL_HELPER = missing_tail_helper;
        }
    }
}
