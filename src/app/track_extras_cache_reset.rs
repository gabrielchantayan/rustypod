//! TTrackExtrasCache reset — FUN_081ba16c @ 0x081ba16c.
//! Raw extent [0x081ba16c, 0x081ba1ec): 128 bytes; the next entry starts
//! with its own push. Whole-image ARM decoding finds two inbound plain BLs,
//! zero predicated BLs. Body: four plain BLs, zero predicated BLs, one BLX
//! and one BLXEQ. Clear the dispatched byte, store the low option byte,
//! walk entry objects calling slot +0x14 and, if the option byte is zero
//! after that callback, slot +0x24. Finish with scheduler operation
//! 0x081f73fc and cursor invalidation.
//! Deviations: native-width repr(C) pointers support host fixtures; target
//! offsets are asserted. The unported scheduler operation retains its
//! verified address (no inferred callee identity), with a host-only seam.

use crate::util::cursor::{Collection, Cursor, cursor_init, cursor_advance, cursor_invalidate};
use core::ptr;

#[repr(C)]
pub struct ResetCache {
    pub unresolved: [u32; 18],
    pub scheduler: *mut u8,
    pub entries: Collection,
    pub reserved: [u8; 20],
    pub dispatched: u8,
    pub reset_option: u8,
}

#[repr(C)]
pub struct ResetEntry { pub object: *mut ResetObject }
#[repr(C)]
pub struct ResetObject { pub vtable: *const ResetVtable }
#[repr(C)]
pub struct ResetVtable {
    pub unresolved_00_to_10: [usize; 5],
    pub on_reset: unsafe extern "C" fn(*mut ResetObject),
    pub unresolved_18_to_20: [usize; 3],
    pub on_full_reset: unsafe extern "C" fn(*mut ResetObject),
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(ResetCache, scheduler) == 0x48);
    assert!(core::mem::offset_of!(ResetCache, entries) == 0x4c);
    assert!(core::mem::offset_of!(ResetCache, dispatched) == 0x64);
    assert!(core::mem::offset_of!(ResetCache, reset_option) == 0x65);
    assert!(core::mem::offset_of!(ResetVtable, on_reset) == 0x14);
    assert!(core::mem::offset_of!(ResetVtable, on_full_reset) == 0x24);
};

pub type ResetSchedulerOperation = unsafe extern "C" fn(*mut u8);
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_scheduler_operation(_: *mut u8) {
    panic!("install cache-reset scheduler host operation")
}
#[cfg(not(target_os = "none"))]
pub static mut TRACK_EXTRAS_CACHE_RESET_SCHEDULER: ResetSchedulerOperation = missing_scheduler_operation;

/// Reset every entry, optionally invoking the second reset callback.
///
/// # Safety
/// Cache, collection entries, objects and callback slots must be valid.
/// Callbacks may change the option or entry object; any replacement must
/// remain valid. The scheduler must satisfy retail operation 0x081f73fc.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn track_extras_cache_reset(cache: *mut ResetCache, option: u32) {
    (*cache).dispatched = 0;
    (*cache).reset_option = option as u8;
    let mut cursor = Cursor { collection: ptr::null_mut(), index: 0 };
    cursor_init(&mut cursor, ptr::addr_of_mut!((*cache).entries));
    let mut entry: *mut ResetEntry = ptr::null_mut();
    while cursor_advance(&mut cursor, ptr::addr_of_mut!(entry).cast()) != 0 {
        let object = (*entry).object;
        ((*(*object).vtable).on_reset)(object);
        if (*cache).reset_option == 0 {
            let object = (*entry).object;
            ((*(*object).vtable).on_full_reset)(object);
        }
    }
    #[cfg(target_os = "none")]
    let finish: ResetSchedulerOperation = core::mem::transmute(0x081f_73fcusize);
    #[cfg(not(target_os = "none"))]
    let finish = ptr::read_volatile(ptr::addr_of!(TRACK_EXTRAS_CACHE_RESET_SCHEDULER));
    finish((*cache).scheduler);
    cursor_invalidate(&mut cursor);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::util::cursor::CollectionVtable;
    use std::vec::Vec;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());

    #[repr(C)]
    struct Fixture { cache: ResetCache, items: Vec<*mut ResetEntry>, events: Vec<u32> }
    #[repr(C)]
    struct Object { base: ResetObject, fixture: *mut Fixture, id: u32, change: i32, replacement: *mut ResetObject, entry: *mut ResetEntry }
    unsafe extern "C" fn item_at(collection: *mut Collection, index: i32, out: *mut u8) -> u32 {
        let fixture = &mut *((collection.cast::<u8>()).sub(core::mem::offset_of!(ResetCache, entries)) as *mut Fixture);
        match fixture.items.get(index as usize) {
            Some(&item) => { out.cast::<*mut ResetEntry>().write(item); 7 }
            None => 0,
        }
    }
    unsafe extern "C" fn reset(object: *mut ResetObject) {
        let o = &mut *object.cast::<Object>();
        let f = &mut *o.fixture;
        assert_eq!(f.cache.dispatched, 0);
        f.events.push(o.id);
        if o.change >= 0 { f.cache.reset_option = o.change as u8; }
        if !o.replacement.is_null() { (*o.entry).object = o.replacement; }
    }
    unsafe extern "C" fn full_reset(object: *mut ResetObject) {
        let o = &mut *object.cast::<Object>();
        (*o.fixture).events.push(o.id + 100);
    }
    unsafe extern "C" fn finish(scheduler: *mut u8) {
        (*scheduler.cast::<Fixture>()).events.push(999);
    }
    static COLLECTION_VTABLE: CollectionVtable = CollectionVtable { unresolved: [0; 15], item_at };
    static OBJECT_VTABLE: ResetVtable = ResetVtable {
        unresolved_00_to_10: [0; 5], on_reset: reset,
        unresolved_18_to_20: [0; 3], on_full_reset: full_reset,
    };

    #[test]
    fn empty_options_callback_mutation_and_object_replacement() {
        let _guard = LOCK.lock();
        unsafe { TRACK_EXTRAS_CACHE_RESET_SCHEDULER = finish; }
        for (option, count, change, replace, expected) in [
            (0, 0, -1, false, std::vec![999]),
            (0, 2, -1, false, std::vec![1, 101, 2, 102, 999]),
            (1, 2, -1, false, std::vec![1, 2, 999]),
            (256, 2, -1, false, std::vec![1, 101, 2, 102, 999]),
            (0, 2, 1, false, std::vec![1, 2, 999]),
            (1, 2, 0, true, std::vec![1, 103, 2, 102, 999]),
        ] {
            let mut f = Fixture { cache: ResetCache { unresolved: [0; 18], scheduler: ptr::null_mut(), entries: Collection { vtable: &COLLECTION_VTABLE }, reserved: [0xa5; 20], dispatched: 9, reset_option: 9 }, items: Vec::new(), events: Vec::new() };
            let fp = ptr::addr_of_mut!(f);
            f.cache.scheduler = fp.cast();
            let mut objects = [1, 2, 3].map(|id| Object { base: ResetObject { vtable: &OBJECT_VTABLE }, fixture: fp, id, change: -1, replacement: ptr::null_mut(), entry: ptr::null_mut() });
            let mut entries = objects.each_mut().map(|o| ResetEntry { object: &mut o.base });
            objects[0].change = change;
            if replace { objects[0].replacement = &mut objects[2].base; objects[0].entry = &mut entries[0]; }
            f.items = entries[..count].iter_mut().map(|e| e as *mut _).collect();
            unsafe { track_extras_cache_reset(&mut f.cache, option); }
            assert_eq!(f.events, expected);
            assert_eq!(f.cache.reset_option, if change < 0 { option as u8 } else { change as u8 });
            assert_eq!(f.cache.dispatched, 0);
            assert_eq!(f.cache.reserved, [0xa5; 20]);
        }
    }
}
