//! Cached position membership across selected entries.
//!
//! `FUN_08299c6c` @ `0x08299c6c`: 172 bytes through `0x08299d18`,
//! including the `0x36a1` literal at `0x08299d14`. Raw ARM has five
//! unconditional outbound BLs, two unconditional inbound BLs, and no
//! predicated BLs. The next function starts at `0x08299d18`.
//! Cache byte 1 means a hit, 2 means a miss; other values trigger an
//! inclusive signed-index scan of the selected-or-all range. Stop on the
//! first entry containing the position, cache 1 or 2, and return 0x36a1
//! or zero. Deliberate deviations: reuse the existing range/item ports;
//! unported cache and membership calls retain verified firmware addresses
//! on target and explicit host seams. Only r0 is returned: Ghidra's u64
//! return is spurious (the epilogue merely restores saved argument r1).

use crate::app::opaque_collection_item_at::opaque_collection_item_at;
use crate::util::selected_or_all_entry_range::selected_or_all_entry_range;

type CacheGet = unsafe extern "C" fn(*mut u8, u32) -> u32;
type CacheSet = unsafe extern "C" fn(*mut u8, u32, u32);
type Contains = unsafe extern "C" fn(*mut u8, *mut u32) -> u32;
type ItemAt = unsafe extern "C" fn(*mut u8, usize) -> *mut u8;

#[cfg(not(target_os = "none"))]
pub struct PositionStatusOps {
    pub cache_get: CacheGet,
    pub cache_set: CacheSet,
    pub contains: Contains,
    pub item_at: ItemAt,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_get(_: *mut u8, _: u32) -> u32 { panic!("install position cache getter") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_set(_: *mut u8, _: u32, _: u32) { panic!("install position cache setter") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_contains(_: *mut u8, _: *mut u32) -> u32 { panic!("install entry membership query") }
#[cfg(not(target_os = "none"))]
pub static mut POSITION_STATUS_OPS: PositionStatusOps = PositionStatusOps {
    cache_get: missing_get, cache_set: missing_set,
    contains: missing_contains, item_at: opaque_collection_item_at,
};

/// # Safety
/// `owner` has the retailOS layout through its embedded cache at +0x10c;
/// its entry collection and all callees must satisfy their firmware contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selected_entries_position_status(owner: *mut u32, position: u32) -> u32 {
    #[cfg(target_os = "none")]
    let (get, set, contains, item): (CacheGet, CacheSet, Contains, ItemAt) = (
        core::mem::transmute(0x081d_c544usize),
        core::mem::transmute(0x081d_c578usize),
        core::mem::transmute(0x0828_4748usize),
        opaque_collection_item_at,
    );
    #[cfg(not(target_os = "none"))]
    let (get, set, contains, item) = (
        POSITION_STATUS_OPS.cache_get, POSITION_STATUS_OPS.cache_set,
        POSITION_STATUS_OPS.contains, POSITION_STATUS_OPS.item_at,
    );
    let cache = owner.cast::<u8>().add(0x10c);
    match get(cache, position) {
        2 => return 0,
        1 => return 0x36a1,
        _ => {}
    }
    let (mut first, mut last) = (0, 0);
    selected_or_all_entry_range(owner, &mut first, &mut last);
    let mut index = first as i32;
    let mut result = 0;
    while index <= last as i32 {
        let entry = item(owner.add(0xbc / 4).read() as *mut u8, index as u32 as usize);
        let mut query = position;
        if contains(entry, &mut query) != 0 {
            result = 0x36a1;
            break;
        }
        index = index.wrapping_add(1);
    }
    set(cache, position, if result == 0 { 2 } else { 1 });
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut CACHE: [u32; 8] = [0; 8];
    static mut QUERIES: usize = 0;
    static mut ENTRY: [u32; 2] = [3, 5];
    unsafe extern "C" fn get(_: *mut u8, position: u32) -> u32 { CACHE[position as usize] }
    unsafe extern "C" fn set(_: *mut u8, position: u32, state: u32) { CACHE[position as usize] = state; }
    unsafe extern "C" fn item(_: *mut u8, index: usize) -> *mut u8 {
        ENTRY = if index == 7 { [3, 5] } else { [index as u32, index as u32 + 1] };
        core::ptr::addr_of_mut!(ENTRY).cast()
    }
    unsafe extern "C" fn contains(entry: *mut u8, position: *mut u32) -> u32 {
        QUERIES += 1;
        let bounds = entry.cast::<u32>();
        let value = position.read();
        // The caller must not propagate a callee's modified query into the cache key.
        position.write(0);
        (value >= bounds.read() && value < bounds.add(1).read()) as u32
    }

    #[test]
    fn membership_boundaries_cache_hits_and_misses_by_original_position() {
        let _guard = LOCK.lock();
        unsafe {
            POSITION_STATUS_OPS = PositionStatusOps { cache_get: get, cache_set: set, contains, item_at: item };
            CACHE = [0; 8];
            QUERIES = 0;
            let mut owner = [0u32; 0x280 / 4];
            owner[0xf4 / 4] = 7;
            for (position, expected) in [(2, 0), (3, 0x36a1), (4, 0x36a1), (5, 0)] {
                assert_eq!(selected_entries_position_status(owner.as_mut_ptr(), position), expected);
                assert_eq!(CACHE[position as usize], if expected == 0 { 2 } else { 1 });
            }
            assert_eq!(QUERIES, 4);
            ENTRY = [0, 0];
            for (position, expected) in [(2, 0), (3, 0x36a1), (4, 0x36a1), (5, 0)] {
                assert_eq!(selected_entries_position_status(owner.as_mut_ptr(), position), expected);
            }
            assert_eq!(QUERIES, 4);
            let slab = crate::testing::try_map_u32_slab(
                crate::testing::hints::SELECTED_ENTRIES_POSITION_STATUS, 0x1000,
            ).expect("low-address collection fixture");
            let collection = slab.cast::<u32>();
            owner[0xbc / 4] = collection as u32;
            owner[0xf4 / 4] = u32::MAX;
            collection.add(2).write(0);
            CACHE[6] = 0;
            QUERIES = 0;
            assert_eq!(selected_entries_position_status(owner.as_mut_ptr(), 6), 0);
            assert_eq!(QUERIES, 0, "empty count wraps to signed -1");
            collection.add(2).write(8);
            CACHE[3] = 0;
            assert_eq!(selected_entries_position_status(owner.as_mut_ptr(), 3), 0x36a1);
            assert_eq!(QUERIES, 4, "stop at first match");
            CACHE[6] = 0;
            assert_eq!(selected_entries_position_status(owner.as_mut_ptr(), 6), 0x36a1);
            assert_eq!(QUERIES, 11);
            POSITION_STATUS_OPS = PositionStatusOps { cache_get: missing_get, cache_set: missing_set, contains: missing_contains, item_at: opaque_collection_item_at };
            ENTRY = [3, 5];
        }
    }
}
