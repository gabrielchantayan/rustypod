//! First collection-item word at +0x1c for a UI owner.
//!
//! `ui_collection_first_item_word_at_1c` — original: `FUN_081476dc` @
//! **0x081476dc**, 40 bytes (`0x081476dc..0x08147704`; the next separately
//! entered function begins at `0x08147704`). Whole-image ARM B/BL decoding
//! finds exactly five inbound plain unconditional `bl` calls — `0x081a1bb0`,
//! `0x081a1c54`, `0x081a1dbc`, `0x081a1e20`, and `0x081a1e88` — and no
//! predicated calls.
//!
//! # Algorithm
//!
//! Load the opaque collection pointer from the UI owner at +0xa4. If its count
//! word at +0x04 is zero, return -1. Otherwise call `FUN_083d5f5c` with index
//! zero and return word +0x1c of the selected item.
//!
//! # Deliberate deviation
//!
//! `FUN_083d5f5c` has no recovered name in `names.yaml`; its raw body invokes
//! the collection vtable slot +0x40 and dereferences that result. This port
//! retains it as a volatile dispatch seam so host tests can model its observed
//! ABI without treating host pointers as target-width fields.

use core::ptr;

const COLLECTION_OFFSET: usize = 0xa4;
const COLLECTION_COUNT_OFFSET: usize = 0x04;
const ITEM_WORD_OFFSET: usize = 0x1c;

/// Exact ABI of the unported `FUN_083d5f5c` collection item accessor.
pub type CollectionItemAt = unsafe extern "C" fn(*mut u8, u32) -> *mut u8;

/// Firmware load address of the unported collection item accessor.
pub const COLLECTION_ITEM_AT_ADDRESS: usize = 0x083d_5f5c;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_collection_item_at(collection: *mut u8, index: u32) -> *mut u8 {
    core::mem::transmute::<usize, CollectionItemAt>(COLLECTION_ITEM_AT_ADDRESS)(collection, index)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_collection_item_at(_collection: *mut u8, _index: u32) -> *mut u8 {
    panic!("ui_collection_first_item_word_at_1c requires FUN_083d5f5c")
}

/// Dispatch seam for the unported `FUN_083d5f5c` collection item accessor.
#[cfg(target_os = "none")]
pub static mut COLLECTION_ITEM_AT: CollectionItemAt = retail_collection_item_at;

/// Host-test dispatch seam for the unported collection item accessor.
#[cfg(not(target_os = "none"))]
pub static mut COLLECTION_ITEM_AT: CollectionItemAt = missing_collection_item_at;

/// Returns the first collection item's opaque word at +0x1c, or -1 if empty.
///
/// # Safety
///
/// `owner` must be readable through +0xa4. Its collection pointer must be
/// valid through +0x04; for a nonempty collection the installed accessor must
/// return an item readable through +0x1c. RetailOS performs no other checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_collection_first_item_word_at_1c(owner: *mut u8) -> u32 {
    let collection = (owner.add(COLLECTION_OFFSET) as *const u32).read() as usize as *mut u8;
    if (collection.add(COLLECTION_COUNT_OFFSET) as *const u32).read() == 0 {
        u32::MAX
    } else {
        let item_at = ptr::read_volatile(ptr::addr_of!(COLLECTION_ITEM_AT));
        (item_at(collection, 0).add(ITEM_WORD_OFFSET) as *const u32).read()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut MOCK_COLLECTION: *mut u8 = ptr::null_mut();
    static mut MOCK_INDEX: u32 = u32::MAX;
    static mut MOCK_ITEM: *mut u8 = ptr::null_mut();

    struct DispatchGuard;

    impl Drop for DispatchGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(COLLECTION_ITEM_AT).write_volatile(missing_collection_item_at);
            }
        }
    }

    unsafe extern "C" fn recording_item_at(collection: *mut u8, index: u32) -> *mut u8 {
        MOCK_COLLECTION = collection;
        MOCK_INDEX = index;
        MOCK_ITEM
    }

    unsafe fn install_mock(item: *mut u8) {
        MOCK_COLLECTION = ptr::null_mut();
        MOCK_INDEX = u32::MAX;
        MOCK_ITEM = item;
        ptr::addr_of_mut!(COLLECTION_ITEM_AT).write_volatile(recording_item_at);
    }

    unsafe fn fixture() -> Option<*mut u8> {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::UI_COLLECTION_FIRST_ITEM_WORD_AT_1C,
            0x1000,
        )
    }

    #[test]

    fn empty_collection_short_circuits_and_nonempty_collection_returns_item_word() {
        let _lock = DISPATCH_LOCK.lock();
        let _restore = DispatchGuard;
        let Some(slab) = (unsafe { fixture() }) else {
            crate::testing::note_missing_u32_fixture(module_path!());
            return;
        };
        unsafe {
            let owner = slab;
            let collection = slab.add(0x200);
            let item = slab.add(0x300);
            (owner.add(COLLECTION_OFFSET) as *mut u32).write(collection as usize as u32);
            install_mock(item);
            (collection.add(COLLECTION_COUNT_OFFSET) as *mut u32).write(0);
            assert_eq!(ui_collection_first_item_word_at_1c(owner), u32::MAX);
            assert!(MOCK_COLLECTION.is_null());

            (collection.add(COLLECTION_COUNT_OFFSET) as *mut u32).write(1);
            (item.add(ITEM_WORD_OFFSET) as *mut u32).write(0xfeed_c0de);
            assert_eq!(ui_collection_first_item_word_at_1c(owner), 0xfeed_c0de);
            assert_eq!(MOCK_COLLECTION, collection);
            assert_eq!(MOCK_INDEX, 0);
        }
    }
}
