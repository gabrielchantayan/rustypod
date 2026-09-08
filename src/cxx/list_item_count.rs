//! Item-count query forwarded through an embedded collection object.
//!
//! `list_item_count` — original: `FUN_082a6888` @ 0x082a6888 (16 bytes).
//! Raw ARM: `ldr r0,[r0,#0xec]; ldr r1,[r0]; ldr r1,[r1,#0x170]; bx r1`.
//! The next separately linked function begins at 0x082a6898, confirming the
//! supplied 16-byte extent. Decoding every ARM B/BL word in osos.dec finds 19
//! direct inbound calls, all unconditional `bl`; no predicated forms or tail
//! branches target this entry.
//!
//! Algorithm: load the collection object stored as a 32-bit target pointer at
//! `list + 0xec`, load its vtable, and invoke slot +0x170 with that collection
//! object as `r0`. Callers use the returned word as a list-item count. The
//! concrete collection class and virtual target are unrecovered, so this port
//! deliberately dispatches through the object's vtable rather than naming an
//! invented callee.
//!
//! Deviation: Rust expresses the terminal `bx` as the final call and returns
//! its value. No observable work follows it, preserving the return register.
//! The embedded pointer stays a `u32` on every target; host fixtures therefore
//! use a below-4-GiB mapping rather than a host-width field at a false offset.

/// Byte offset of the nested collection's 32-bit target pointer.
const COLLECTION_OFFSET: usize = 0xec;

/// Word index for collection vtable slot +0x170 on ARMv5TE.
const ITEM_COUNT_VTABLE_INDEX: usize = 0x170 / 4;

/// ABI of the unrecovered collection item-count virtual method.
type CollectionItemCount = unsafe extern "C" fn(*mut u8) -> usize;

/// list_item_count — original: `FUN_082a6888` @ 0x082a6888 (16 bytes).
///
/// Returns the value from the collection object's unchecked vtable slot
/// +0x170. The collection lives in the caller's list object at +0xec as a
/// 32-bit target pointer; neither dereference nor the terminal target has a
/// NULL guard in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_item_count(list: *mut u8) -> usize {
    let collection = unsafe { list.add(COLLECTION_OFFSET).cast::<u32>().read() as usize as *mut u8 };
    let vtable = unsafe { collection.cast::<*const usize>().read() };
    let entry = unsafe { vtable.add(ITEM_COUNT_VTABLE_INDEX).read() };
    let item_count: CollectionItemCount = unsafe { core::mem::transmute(entry) };
    unsafe { item_count(collection) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;
    const COLLECTION_A_OFFSET: usize = 0x200;
    const COLLECTION_B_OFFSET: usize = 0x300;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::LIST_ITEM_COUNT, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED_COLLECTION: usize = 0;

    unsafe extern "C" fn wrong_slot(_collection: *mut u8) -> usize {
        0xfeed_face
    }

    unsafe extern "C" fn collection_a_count(collection: *mut u8) -> usize {
        unsafe { FORWARDED_COLLECTION = collection as usize };
        37
    }

    unsafe extern "C" fn collection_b_count(_collection: *mut u8) -> usize {
        91
    }

    fn fixture() -> Option<*mut u8> {
        let base = (*FIXTURE)? as *mut u8;
        unsafe { core::ptr::write_bytes(base, 0, FIXTURE_LEN) };
        Some(base)
    }

    fn lock() -> MutexGuard<'static, ()> {
        match DISPATCH_LOCK.lock() {
            Ok(lock) => lock,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[test]
    fn forwards_embedded_collection_to_vtable_slot_0x170() {
        let _lock = lock();
        let Some(list) = fixture() else {
            note_missing_u32_fixture("cxx::list_item_count");
            return;
        };
        let collection = unsafe { list.add(COLLECTION_A_OFFSET) };
        let mut vtable = [wrong_slot as usize; ITEM_COUNT_VTABLE_INDEX + 1];
        vtable[ITEM_COUNT_VTABLE_INDEX] = collection_a_count as usize;

        unsafe {
            collection.cast::<*const usize>().write(vtable.as_ptr());
            list.add(COLLECTION_OFFSET).cast::<u32>().write(collection as usize as u32);
            FORWARDED_COLLECTION = 0;
        }

        assert_eq!(unsafe { list_item_count(list) }, 37);
        assert_eq!(unsafe { FORWARDED_COLLECTION }, collection as usize);
    }

    #[test]
    fn reads_a_target_word_at_exactly_offset_0xec() {
        let _lock = lock();
        let Some(list) = fixture() else {
            note_missing_u32_fixture("cxx::list_item_count");
            return;
        };
        let collection_a = unsafe { list.add(COLLECTION_A_OFFSET) };
        let collection_b = unsafe { list.add(COLLECTION_B_OFFSET) };
        let mut vtable_a = [wrong_slot as usize; ITEM_COUNT_VTABLE_INDEX + 1];
        let mut vtable_b = [wrong_slot as usize; ITEM_COUNT_VTABLE_INDEX + 1];
        vtable_a[ITEM_COUNT_VTABLE_INDEX] = collection_a_count as usize;
        vtable_b[ITEM_COUNT_VTABLE_INDEX] = collection_b_count as usize;

        unsafe {
            collection_a.cast::<*const usize>().write(vtable_a.as_ptr());
            collection_b.cast::<*const usize>().write(vtable_b.as_ptr());
            list.add(COLLECTION_OFFSET).cast::<u32>().write(collection_a as usize as u32);
            list.add(COLLECTION_OFFSET + 4).cast::<u32>().write(collection_b as usize as u32);
        }

        assert_eq!(unsafe { list_item_count(list) }, 37);
    }
}
