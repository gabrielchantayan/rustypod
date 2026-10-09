//! Clear an owned entry collection through its entries' virtual slot +4.
//!
//! Original: FUN_08104a84 at 0x08104a84, 84 bytes, ending at the next
//! constructor prologue at 0x08104ad8. Raw A32 decoding verifies two plain
//! inbound BLs (0x08104b48, 0x08280e40), zero predicated inbound BLs,
//! zero internal BLs, one BLXNE through virtual slot +4, and a tail B to
//! 0x083e5140. Iterate with an eight-bit index, reloading the count and
//! vector after callbacks; skip null entries. Zero the count, then erase
//! the whole vector and return its begin pointer. Slot identity is unresolved.
//! Deliberate deviations: inline the verified erase-all specialization of
//! 0x083e5140 (no copies or element destruction), dropping its inert pointer
//! walk. repr(C) pointer fields widen on hosts but preserve target field order.

#[repr(C)]
pub struct OwnedEntryVtable {
    pub reserved: usize,
    pub clear_owned: unsafe extern "C" fn(*mut OwnedEntry),
}

#[repr(C)]
pub struct OwnedEntry {
    pub vtable: *const OwnedEntryVtable,
}

#[repr(C)]
pub struct OwnedEntryCollection {
    pub vtable: usize,
    pub begin: *mut *mut OwnedEntry,
    pub end: *mut *mut OwnedEntry,
    pub capacity_end: *mut *mut OwnedEntry,
    pub reserved_10_33: [u32; 9],
    pub count: u8,
}

/// # Safety
/// The collection, its count-sized pointer array, and non-null entries' slot
/// +4 must be valid. Callbacks may change the count or replace the array;
/// any replacement must remain valid for the next iteration.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_entry_collection_clear(
    collection: *mut OwnedEntryCollection,
) -> *mut *mut OwnedEntry {
    let mut index = 0u8;
    while index < core::ptr::addr_of!((*collection).count).read() {
        let begin = core::ptr::addr_of!((*collection).begin).read();
        let entry = begin.add(index as usize).read();
        if !entry.is_null() {
            let vtable = core::ptr::addr_of!((*entry).vtable).read();
            ((*vtable).clear_owned)(entry);
        }
        index = index.wrapping_add(1);
    }
    core::ptr::addr_of_mut!((*collection).count).write(0);
    let begin = core::ptr::addr_of!((*collection).begin).read();
    core::ptr::addr_of_mut!((*collection).end).write(begin);
    begin
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[repr(C)]
    struct Entry {
        interface: OwnedEntry,
        calls: u32,
        owner: *mut OwnedEntryCollection,
        replacement: *mut *mut OwnedEntry,
        new_count: u8,
    }

    unsafe extern "C" fn clear(entry: *mut OwnedEntry) {
        let entry = entry.cast::<Entry>();
        (*entry).calls += 1;
        if !(*entry).owner.is_null() {
            (*(*entry).owner).count = (*entry).new_count;
            if !(*entry).replacement.is_null() {
                (*(*entry).owner).begin = (*entry).replacement;
            }
        }
    }

    static VTABLE: OwnedEntryVtable = OwnedEntryVtable { reserved: 0, clear_owned: clear };

    fn entry() -> Entry {
        Entry { interface: OwnedEntry { vtable: &VTABLE }, calls: 0,
            owner: ptr::null_mut(), replacement: ptr::null_mut(), new_count: 0 }
    }

    fn collection(begin: *mut *mut OwnedEntry, length: usize, count: u8) -> OwnedEntryCollection {
        OwnedEntryCollection { vtable: 0, begin, end: begin.wrapping_add(length),
            capacity_end: begin.wrapping_add(length), reserved_10_33: [0; 9], count }
    }

    #[test]
    fn empty_null_vector_and_zero_count_with_nonempty_vector() {
        let mut empty = collection(ptr::null_mut(), 0, 0);
        assert!(unsafe { owned_entry_collection_clear(&mut empty) }.is_null());
        let mut item = entry();
        let mut slots = [&mut item.interface as *mut _, ptr::null_mut()];
        let mut owner = collection(slots.as_mut_ptr(), 2, 0);
        let capacity = owner.capacity_end;
        assert_eq!(unsafe { owned_entry_collection_clear(&mut owner) }, slots.as_mut_ptr());
        assert_eq!(owner.end, owner.begin);
        assert_eq!(owner.capacity_end, capacity);
        assert_eq!(item.calls, 0);
        assert_eq!(slots[0], &mut item.interface as *mut _);
    }

    #[test]
    fn skips_nulls_preserves_slots_and_handles_maximum_count() {
        let mut item = entry();
        let mut slots = [ptr::null_mut(); 255];
        for index in [0, 127, 254] { slots[index] = &mut item.interface; }
        let before = slots;
        let mut owner = collection(slots.as_mut_ptr(), 255, 255);
        unsafe { owned_entry_collection_clear(&mut owner); }
        assert_eq!(item.calls, 3);
        assert_eq!(owner.count, 0);
        assert_eq!(owner.end, owner.begin);
        assert_eq!(slots, before);
    }

    #[test]
    fn callbacks_can_shrink_count_or_replace_vector_and_grow_count() {
        for grow in [false, true] {
            let mut first = entry();
            let mut second = entry();
            let mut slots = [&mut first.interface as *mut _, ptr::null_mut()];
            let mut replacement = [ptr::null_mut(), &mut second.interface as *mut _];
            let mut owner = collection(slots.as_mut_ptr(), 2, if grow { 1 } else { 2 });
            first.owner = &mut owner;
            first.new_count = if grow { 2 } else { 0 };
            if grow { first.replacement = replacement.as_mut_ptr(); }
            let expected = if grow { replacement.as_mut_ptr() } else { slots.as_mut_ptr() };
            assert_eq!(unsafe { owned_entry_collection_clear(&mut owner) }, expected);
            assert_eq!(first.calls, 1);
            assert_eq!(second.calls, if grow { 1 } else { 0 });
            assert_eq!(owner.count, 0);
            assert_eq!(owner.end, expected);
        }
    }
}
