//! `collection_item_at` — original: `FUN_0826ba9c` @ `0x0826ba9c` (40
//! bytes; true extent `0x0826ba9c..0x0826bac4`, immediately followed by
//! `FUN_0826bac4`).
//!
//! Raw ARM decoding finds five direct incoming calls, all unconditional plain
//! `bl` (at `0x0812d390`, `0x0812d4bc`, `0x081880f8`, `0x08188128`, and
//! `0x082894d4`); there are no predicated calls. The wrapper loads the
//! collection object at `collection + 4`, initializes a stack result word to
//! zero, calls that object's vtable slot `+0x3c` as `(object, index, &result)`,
//! and returns the result word. The method's own return value is discarded.
//!
//! The virtual method is runtime data, not a statically identified firmware
//! callee. Deliberate deviation: it is behind [`COLLECTION_ITEM_AT_DISPATCH`]
//! so host tests can record the ABI; target builds perform the exact two
//! dereferences, slot load, and indirect call.

/// Signature of the collection vtable's `+0x3c` indexed-item method.
pub type CollectionItemMethod = unsafe extern "C" fn(*mut u8, u32, *mut u32) -> u32;

const VTABLE_ITEM_AT_OFFSET: usize = 0x3c;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_collection_item_at_dispatch(
    collection: *mut u8,
    index: u32,
    result: *mut u32,
) {
    let object = (collection.add(4) as *const *mut u8).read_unaligned();
    let vtable = (object as *const *const u8).read_unaligned();
    let method = (vtable.add(VTABLE_ITEM_AT_OFFSET) as *const CollectionItemMethod).read_unaligned();
    method(object, index, result);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_collection_item_at_dispatch(
    _collection: *mut u8,
    _index: u32,
    _result: *mut u32,
) {
    panic!("collection_item_at requires its retailOS vtable method")
}

#[cfg(target_os = "none")]
const DEFAULT_COLLECTION_ITEM_AT_DISPATCH: unsafe extern "C" fn(*mut u8, u32, *mut u32) =
    firmware_collection_item_at_dispatch;
#[cfg(not(target_os = "none"))]
const DEFAULT_COLLECTION_ITEM_AT_DISPATCH: unsafe extern "C" fn(*mut u8, u32, *mut u32) =
    missing_collection_item_at_dispatch;

/// Runtime dispatch through the unported vtable slot `+0x3c` method.
pub static mut COLLECTION_ITEM_AT_DISPATCH: unsafe extern "C" fn(*mut u8, u32, *mut u32) =
    DEFAULT_COLLECTION_ITEM_AT_DISPATCH;

/// Returns the item which `collection` resolves at `index` through vtable slot
/// `+0x3c`. The collection and its method must be valid; retailOS has no null
/// checks for either.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn collection_item_at(collection: *mut u8, index: u32) -> u32 {
    let dispatch = core::ptr::read_volatile(core::ptr::addr_of!(COLLECTION_ITEM_AT_DISPATCH));
    let mut result = 0;
    dispatch(collection, index, core::ptr::addr_of_mut!(result));
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut RECEIVED_COLLECTION: *mut u8 = core::ptr::null_mut();
    static mut RECEIVED_INDEX: u32 = 0;

    unsafe extern "C" fn recording_dispatch(collection: *mut u8, index: u32, result: *mut u32) {
        RECEIVED_COLLECTION = collection;
        RECEIVED_INDEX = index;
        result.write(index ^ 0xa5a5_5a5a);
    }

    struct DispatchGuard;
    impl Drop for DispatchGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(COLLECTION_ITEM_AT_DISPATCH)
                    .write_volatile(DEFAULT_COLLECTION_ITEM_AT_DISPATCH);
            }
        }
    }

    #[test]
    fn forwards_collection_and_full_width_index_then_returns_out_word() {
        let _lock = DISPATCH_LOCK.lock();
        let _restore = DispatchGuard;
        let mut collection = [0u8; 8];
        unsafe {
            core::ptr::addr_of_mut!(COLLECTION_ITEM_AT_DISPATCH).write_volatile(recording_dispatch);
            let item = collection_item_at(collection.as_mut_ptr(), 0xffff_fffe);
            assert_eq!(RECEIVED_COLLECTION, collection.as_mut_ptr());
            assert_eq!(RECEIVED_INDEX, 0xffff_fffe);
            assert_eq!(item, 0x5a5a_a5a4);
        }
    }
}
