//! Release and delete the first non-null indexed value from an enabled collection.
//!
//! `collection_release_first_indexed_value` — original: `FUN_0839be84` @
//! `0x0839be84`.
//!
//! **96 bytes** (`0x0839be84..0x0839bee0`): twenty-four A32 words from `push
//! {r4,r5,r6,r7,r8,lr}` through `pop {r4,r5,r6,r7,r8,pc}`; `0x0839bee4`
//! starts the next real function. Raw decoding verifies two unconditional plain
//! direct `bl` instructions (at `0x0839bec8` and `0x0839bed0`) and no
//! predicated direct `bl`; its vtable `+0x40` dispatch is an unconditional
//! indirect `blx`. Whole-image A32 branch decoding finds two inbound plain
//! `bl` sites and no predicated inbound sites.
//!
//! # Algorithm
//!
//! If byte `+0x28` is clear, return. Otherwise scan signed indices
//! `[0, *(i32 *)(this + 4))`; the vtable `+0x40` method returns a pointer to a
//! word containing each value. On the first non-null value, call
//! `FUN_081292cc`, which drains its linked entries at `+0x04` and stores a new
//! value at `+0x0c`, then tag-2 `operator_delete` the value.
//!
//! # Deliberate deviations
//!
//! `FUN_081292cc` has no ledger identity, so ARM calls its verified fixed load
//! address through a typed operation; host builds use an injectable operation.
//! Rust expands the indexed virtual dispatch to preserve target-width vtable
//! words while keeping host fixtures native-width.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_RELEASE_INDEXED_VALUE: usize = 0x0812_92cc;
const COUNT_OFFSET: usize = 4;
const ENABLED_OFFSET: usize = 0x28;

#[cfg(not(target_os = "none"))]
pub struct CollectionReleaseFirstIndexedValueOps {
    pub value_at: unsafe extern "C" fn(*mut u8, i32) -> *mut u8,
    pub release: unsafe extern "C" fn(*mut u8),
    pub delete: unsafe extern "C" fn(*mut u8),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_value_at(_collection: *mut u8, _index: i32) -> *mut u8 {
    panic!("install collection release host operations before calling")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(_value: *mut u8) {
    panic!("install collection release host operations before calling")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_delete(_value: *mut u8) {
    panic!("install collection release host operations before calling")
}

#[cfg(not(target_os = "none"))]
pub static mut COLLECTION_RELEASE_FIRST_INDEXED_VALUE_OPS: CollectionReleaseFirstIndexedValueOps = CollectionReleaseFirstIndexedValueOps {
    value_at: missing_value_at,
    release: missing_release,
    delete: missing_delete,
};

#[cfg(target_os = "none")]
unsafe fn value_at(collection: *mut u8, index: i32) -> *mut u8 {
    type ValueAt = unsafe extern "C" fn(*mut u8, i32) -> *const u32;
    let vtable = unsafe { collection.cast::<u32>().read_volatile() as usize as *const u8 };
    let method: ValueAt = unsafe { vtable.add(0x40).cast::<ValueAt>().read_volatile() };
    unsafe { method(collection, index).read_volatile() as usize as *mut u8 }
}

#[cfg(not(target_os = "none"))]
unsafe fn value_at(collection: *mut u8, index: i32) -> *mut u8 {
    let ops = unsafe { core::ptr::read_volatile(addr_of!(COLLECTION_RELEASE_FIRST_INDEXED_VALUE_OPS)) };
    unsafe { (ops.value_at)(collection, index) }
}

#[cfg(target_os = "none")]
unsafe fn release(value: *mut u8) {
    let release: unsafe extern "C" fn(*mut u8) = unsafe { core::mem::transmute(RETAIL_RELEASE_INDEXED_VALUE) };
    unsafe { release(value) }
}

#[cfg(not(target_os = "none"))]
unsafe fn release(value: *mut u8) {
    let ops = unsafe { core::ptr::read_volatile(addr_of!(COLLECTION_RELEASE_FIRST_INDEXED_VALUE_OPS)) };
    unsafe { (ops.release)(value) }
}

#[cfg(target_os = "none")]
unsafe fn delete(value: *mut u8) {
    unsafe { crate::heap::veneers::operator_delete(value) }
}

#[cfg(not(target_os = "none"))]
unsafe fn delete(value: *mut u8) {
    let ops = unsafe { core::ptr::read_volatile(addr_of!(COLLECTION_RELEASE_FIRST_INDEXED_VALUE_OPS)) };
    unsafe { (ops.delete)(value) }
}

/// Scan an enabled collection and release then delete its first non-null value.
///
/// # Safety
///
/// `collection` must be readable through `+0x28`. When enabled, its signed
/// count at `+0x04` and every vtable-selected value must be valid as retailOS
/// requires; the original performs no NULL or bounds validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn collection_release_first_indexed_value(collection: *mut u8) {
    if unsafe { collection.add(ENABLED_OFFSET).read_volatile() } == 0 {
        return;
    }
    let count = unsafe { collection.add(COUNT_OFFSET).cast::<i32>().read_volatile() };
    let mut index = 0;
    while index < count {
        let value = unsafe { value_at(collection, index) };
        if !value.is_null() {
            unsafe { release(value) };
            unsafe { delete(value) };
            return;
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut VALUES: [*mut u8; 4] = [core::ptr::null_mut(); 4];
    static mut VALUE_CALLS: [i32; 4] = [0; 4];
    static mut VALUE_CALL_COUNT: usize = 0;
    static mut RELEASED: *mut u8 = core::ptr::null_mut();
    static mut DELETED: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn value_at(_collection: *mut u8, index: i32) -> *mut u8 {
        unsafe {
            VALUE_CALLS[VALUE_CALL_COUNT] = index;
            VALUE_CALL_COUNT += 1;
            VALUES[index as usize]
        }
    }

    unsafe extern "C" fn release(value: *mut u8) {
        unsafe { RELEASED = value }
    }

    unsafe extern "C" fn delete(value: *mut u8) {
        unsafe { DELETED = value }
    }

    unsafe fn reset(values: [*mut u8; 4]) {
        unsafe {
            VALUES = values;
            VALUE_CALL_COUNT = 0;
            RELEASED = core::ptr::null_mut();
            DELETED = core::ptr::null_mut();
            COLLECTION_RELEASE_FIRST_INDEXED_VALUE_OPS = CollectionReleaseFirstIndexedValueOps { value_at, release, delete };
        }
    }

    #[test]
    fn disabled_collection_skips_all_dispatch() {
        let _guard = TEST_LOCK.lock();
        let mut collection = [0u32; 11];
        unsafe {
            reset([core::ptr::null_mut(); 4]);
            collection_release_first_indexed_value(collection.as_mut_ptr().cast());
            assert_eq!(VALUE_CALL_COUNT, 0);
        }
    }

    #[test]
    fn releases_and_deletes_the_first_non_null_value_only() {
        let _guard = TEST_LOCK.lock();
        let mut collection = [0u32; 11];
        let mut first = [0u8; 1];
        let mut second = [0u8; 1];
        collection[1] = 4;
        unsafe { collection.as_mut_ptr().cast::<u8>().add(ENABLED_OFFSET).write(1) };
        unsafe {
            reset([core::ptr::null_mut(), first.as_mut_ptr(), second.as_mut_ptr(), core::ptr::null_mut()]);
            collection_release_first_indexed_value(collection.as_mut_ptr().cast());
            assert_eq!(&VALUE_CALLS[..VALUE_CALL_COUNT], &[0, 1]);
            assert_eq!(RELEASED, first.as_mut_ptr());
            assert_eq!(DELETED, first.as_mut_ptr());
        }
    }

    #[test]
    fn non_positive_count_does_not_dispatch() {
        let _guard = TEST_LOCK.lock();
        let mut collection = [0u32; 11];
        collection[1] = (-1i32) as u32;
        unsafe { collection.as_mut_ptr().cast::<u8>().add(ENABLED_OFFSET).write(1) };
        unsafe {
            reset([1usize as *mut u8, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut()]);
            collection_release_first_indexed_value(collection.as_mut_ptr().cast());
            assert_eq!(VALUE_CALL_COUNT, 0);
            assert!(RELEASED.is_null());
            assert!(DELETED.is_null());
        }
    }
}
