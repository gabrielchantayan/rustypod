//! TTrackExtrasCache key search — FUN_081ba1ec @ 0x081ba1ec.
//! True extent [0x081ba1ec, 0x081ba260): 116 bytes. Raw whole-image
//! decoding verifies 2 incoming plain BLs and 0 predicated BLs; the body
//! has 4 plain BLs, 0 predicated BLs and one register BLX.
//! Walk the embedded collection at +0x4c using the existing cursor ports.
//! For each entry, call its object's vtable slot +8 and compare the returned
//! key by pointer identity. Return the first matching entry, or NULL, and
//! invalidate the cursor on either exit.
//! Deviations: Ghidra's extra r2/r3 arguments and u64 return are saved-register
//! artifacts; the ABI takes cache/key in r0/r1 and returns an entry in r0.
//! Typed pointer fields widen naturally on hosts (including prefix padding);
//! the target layout is asserted. No added NULL guards or new callee seams.

//! ARM codegen deliberately permits elimination of cursor_invalidate: it only
//! writes the dead stack-local index. The source preserves both exit calls.
use crate::util::cursor::{Collection, Cursor, cursor_init, cursor_advance, cursor_invalidate};
use core::ptr;

#[repr(C)]
pub struct TrackExtrasCache {
    pub unresolved: [u32; 19],
    pub entries: Collection,
}

#[repr(C)]
pub struct TrackExtrasEntry {
    pub object: *mut TrackExtrasObject,
}

#[repr(C)]
pub struct TrackExtrasObject {
    pub vtable: *const TrackExtrasObjectVtable,
}

#[repr(C)]
pub struct TrackExtrasObjectVtable {
    pub unresolved: [usize; 2],
    pub key: unsafe extern "C" fn(*mut TrackExtrasObject) -> *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(TrackExtrasCache, entries) == 0x4c);
    assert!(core::mem::offset_of!(TrackExtrasObjectVtable, key) == 8);
};

/// Return the first entry whose object's virtual key equals `key`.
/// Cache, entries, objects and their vtables must be valid for the walk.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn track_extras_cache_find_entry(cache: *mut u8, key: *mut u8) -> *mut TrackExtrasEntry {
    let collection = ptr::addr_of_mut!((*(cache as *mut TrackExtrasCache)).entries);
    let mut cursor = Cursor { collection: ptr::null_mut(), index: 0 };
    cursor_init(&mut cursor, collection);
    let mut entry: *mut TrackExtrasEntry = ptr::null_mut();
    while cursor_advance(&mut cursor, ptr::addr_of_mut!(entry).cast()) != 0 {
        let object = (*entry).object;
        if ((*(*object).vtable).key)(object) == key {
            cursor_invalidate(&mut cursor);
            return entry;
        }
    }
    cursor_invalidate(&mut cursor);
    ptr::null_mut()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::util::cursor::CollectionVtable;
    use std::vec::Vec;

    #[repr(C)]
    struct Object {
        base: TrackExtrasObject,
        key: *mut u8,
        calls: usize,
    }
    unsafe extern "C" fn object_key(object: *mut TrackExtrasObject) -> *mut u8 {
        let object = &mut *(object as *mut Object);
        object.calls += 1;
        object.key
    }
    static OBJECT_VTABLE: TrackExtrasObjectVtable = TrackExtrasObjectVtable {
        unresolved: [0; 2], key: object_key,
    };
    #[repr(C)]
    struct Cache {
        base: TrackExtrasCache,
        items: Vec<*mut TrackExtrasEntry>,
        visited: Vec<i32>,
    }
    unsafe extern "C" fn item_at(collection: *mut Collection, index: i32, out: *mut u8) -> u32 {
        let cache = &mut *((collection as *mut u8)
            .sub(core::mem::offset_of!(TrackExtrasCache, entries)) as *mut Cache);
        cache.visited.push(index);
        match cache.items.get(index as usize) {
            Some(&entry) => { out.cast::<*mut TrackExtrasEntry>().write(entry); 7 }
            None => 0,
        }
    }
    static COLLECTION_VTABLE: CollectionVtable = CollectionVtable {
        unresolved: [0; 15], item_at,
    };

    #[test]
    fn first_match_absent_empty_and_null_key() {
        let mut keys = [1u8, 1u8]; // Equal contents are not equal identities.
        let first = keys.as_mut_ptr();
        let second = unsafe { first.add(1) };
        let mut objects = [first, second, second, ptr::null_mut()].map(|key| Object {
            base: TrackExtrasObject { vtable: &OBJECT_VTABLE }, key, calls: 0,
        });
        let mut entries = objects.each_mut().map(|object| TrackExtrasEntry { object: &mut object.base });
        let mut cache = Cache {
            base: TrackExtrasCache { unresolved: [0; 19], entries: Collection { vtable: &COLLECTION_VTABLE } },
            items: entries.each_mut().map(|entry| entry as *mut _).to_vec(),
            visited: Vec::new(),
        };
        let cache_ptr = ptr::addr_of_mut!(cache.base).cast();
        unsafe {
            assert_eq!(track_extras_cache_find_entry(cache_ptr, second), &mut entries[1] as *mut _);
            assert_eq!(cache.visited, [0, 1]);
            assert_eq!(objects.each_ref().map(|object| object.calls), [1, 1, 0, 0]);
            cache.visited.clear();
            assert_eq!(track_extras_cache_find_entry(cache_ptr, ptr::null_mut()), &mut entries[3] as *mut _);
            assert_eq!(cache.visited, [0, 1, 2, 3]);
            cache.visited.clear();
            let mut absent = 1u8;
            assert!(track_extras_cache_find_entry(cache_ptr, &mut absent).is_null());
            assert_eq!(cache.visited, [0, 1, 2, 3, 4]);
            cache.items.clear();
            cache.visited.clear();
            assert!(track_extras_cache_find_entry(cache_ptr, first).is_null());
            assert_eq!(cache.visited, [0]);
        }
    }
}
