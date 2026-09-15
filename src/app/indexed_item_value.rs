//! `indexed_item_value` — original: `FUN_081d11b8` @ `0x081d11b8`.
//!
//! **52 bytes** (`0x081d11b8..0x081d11e8`); the separately linked next function
//! begins at `0x081d11ec`. Raw ARM contains no plain direct `bl`, no predicated
//! direct `bl`, and one indirect `blx` through the source vtable's `+0x40` slot.
//! Decoding every aligned ARM B/BL-immediate word in `osos.dec` finds five inbound
//! direct calls, all unconditional; no predicated inbound `bl` calls were found.
//!
//! # Algorithm
//!
//! If `index` is less than the signed item count at `object + 0x34`, call the
//! source vtable's `+0x40` method with the embedded source slot at `object +
//! 0x30` and `index`. The method returns a pointer to a value-pointer slot; return
//! zero when that slot contains null, otherwise return the pointed-to word. An
//! index equal to or greater than the count returns zero without dispatch.
//!
//! Deliberate deviation: the vtable method is not identified. Target builds call
//! its verified `+0x40` slot; host builds use a typed seam so tests do not assign
//! an invented callee identity.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

/// Target-width prefix observed by this accessor.
#[repr(C)]
pub struct IndexedItemSource {
    pub opaque_00_to_2c: [u32; 12],
    pub source_vtable: u32,
    pub item_count: i32,
}

const _: [u8; 0x30] = [0; core::mem::offset_of!(IndexedItemSource, source_vtable)];
const _: [u8; 0x34] = [0; core::mem::offset_of!(IndexedItemSource, item_count)];
const _: [u8; 0x38] = [0; core::mem::size_of::<IndexedItemSource>()];

/// Host substitute for the unidentified source vtable method.
#[cfg(not(target_os = "none"))]
pub struct IndexedItemValueOps {
    pub item_at: unsafe extern "C" fn(*mut u8, i32) -> *const *const u32,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_item_at(_source_slot: *mut u8, _index: i32) -> *const *const u32 {
    panic!("install indexed item value host operations before calling")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_INDEXED_ITEM_VALUE_OPS: IndexedItemValueOps = IndexedItemValueOps {
    item_at: missing_item_at,
};

#[cfg(not(target_os = "none"))]
pub static mut INDEXED_ITEM_VALUE_OPS: IndexedItemValueOps = DEFAULT_INDEXED_ITEM_VALUE_OPS;

/// Return an indexed source value, or zero when `index` is at or beyond its count.
///
/// # Safety
///
/// `object` must identify readable, aligned [`IndexedItemSource`] storage. On
/// target, when `index < item_count`, `source_vtable` must identify a readable
/// vtable and its `+0x40` slot must be callable with `object + 0x30`; its returned
/// slot and non-null value pointer must be readable. No NULL or negative-index
/// guard exists in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_item_value(object: *mut IndexedItemSource, index: i32) -> u32 {
    let object = object.cast::<u8>();
    let count = unsafe { object.add(0x34).cast::<i32>().read() };
    if index >= count {
        return 0;
    }

    let source_slot = unsafe { object.add(0x30) };
    #[cfg(target_os = "none")]
    let value_slot = {
        type ItemAt = unsafe extern "C" fn(*mut u8, i32) -> *const *const u32;
        let vtable = unsafe { source_slot.cast::<u32>().read_volatile() as usize as *const u8 };
        let item_at: ItemAt = unsafe { vtable.add(0x40).cast::<ItemAt>().read_volatile() };
        unsafe { item_at(source_slot, index) }
    };
    #[cfg(not(target_os = "none"))]
    let value_slot = {
        let ops = unsafe { core::ptr::read_volatile(addr_of!(INDEXED_ITEM_VALUE_OPS)) };
        unsafe { (ops.item_at)(source_slot, index) }
    };

    let value = unsafe { value_slot.read() };
    if value.is_null() {
        0
    } else {
        unsafe { value.read() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut EXPECTED_SLOT: *mut u8 = core::ptr::null_mut();
    static mut EXPECTED_INDEX: i32 = 0;
    static mut CALLS: u32 = 0;
    static mut VALUE: u32 = 0;
    static mut VALUE_SLOT: *const u32 = core::ptr::null();

    unsafe extern "C" fn item_at(source_slot: *mut u8, index: i32) -> *const *const u32 {
        unsafe {
            assert_eq!(source_slot, EXPECTED_SLOT);
            assert_eq!(index, EXPECTED_INDEX);
            CALLS += 1;
            core::ptr::addr_of!(VALUE_SLOT)
        }
    }

    fn source(count: i32) -> IndexedItemSource {
        IndexedItemSource { opaque_00_to_2c: [0; 12], source_vtable: 0, item_count: count }
    }

    fn install(object: &mut IndexedItemSource, index: i32, value: Option<u32>) {
        unsafe {
            EXPECTED_SLOT = (object as *mut IndexedItemSource).cast::<u8>().add(0x30);
            EXPECTED_INDEX = index;
            CALLS = 0;
            VALUE = value.unwrap_or(0);
            VALUE_SLOT = match value {
                Some(_) => core::ptr::addr_of!(VALUE),
                None => core::ptr::null(),
            };
            INDEXED_ITEM_VALUE_OPS = IndexedItemValueOps { item_at };
        }
    }

    #[test]
    fn dispatches_below_count_and_unwraps_the_returned_value_slot() {
        let _guard = TEST_LOCK.lock();
        let mut object = source(3);
        install(&mut object, 2, Some(0xc001_d00d));

        assert_eq!(unsafe { indexed_item_value(&mut object, 2) }, 0xc001_d00d);
        assert_eq!(unsafe { CALLS }, 1);
    }

    #[test]
    fn equal_or_greater_index_returns_zero_without_dispatch() {
        let _guard = TEST_LOCK.lock();
        let mut object = source(3);
        install(&mut object, 3, Some(0xfeed_face));

        assert_eq!(unsafe { indexed_item_value(&mut object, 3) }, 0);
        assert_eq!(unsafe { CALLS }, 0);
        assert_eq!(unsafe { indexed_item_value(&mut object, 4) }, 0);
        assert_eq!(unsafe { CALLS }, 0);
    }

    #[test]
    fn negative_index_reaches_the_source_and_null_value_returns_zero() {
        let _guard = TEST_LOCK.lock();
        let mut object = source(0);
        install(&mut object, -1, None);

        assert_eq!(unsafe { indexed_item_value(&mut object, -1) }, 0);
        assert_eq!(unsafe { CALLS }, 1);
    }
}
