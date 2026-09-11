//! Current collection-item word for a UI owner.
//!
//! `ui_collection_current_item_word` — original: `FUN_0815d888` @
//! **0x0815d888**, 36 bytes (`0x0815d888..0x0815d8ac`; the separately linked
//! next function starts at `0x0815d8ac`). Whole-image decoding of every ARM
//! B/BL immediate finds exactly 10 inbound calls: all are unconditional plain
//! `bl` instructions; there are no predicated calls or tail branches.
//!
//! # Algorithm
//!
//! If the owner has a nonzero item count at +0x34 and its signed state word at
//! +0x80 is nonnegative, tail-call the collection's slot-16 accessor through
//! the embedded collection handle at +0x2c and return the word it points to.
//! Otherwise return zero. The tail target is `FUN_081d0e00` @ 0x081d0e00,
//! which advances its argument to +0x04, calls that object's vtable slot
//! +0x40, and dereferences the returned word pointer.
//!
//! # Deliberate deviation
//!
//! `FUN_081d0e00` is not recorded in `names.yaml`, so this one-function port
//! retains it as a narrow volatile dispatch seam. Its default is the exact
//! target body; host tests replace the seam to observe the gate without
//! requiring a 32-bit vtable fixture. The collection's semantic item type is
//! not established, so this accessor deliberately names only the returned
//! word rather than inventing a callee or item identity.

/// Offset of the embedded collection handle.
const COLLECTION_HANDLE_OFFSET: usize = 0x2c;
/// Offset of the owner's item count.
const ITEM_COUNT_OFFSET: usize = 0x34;
/// Offset of the signed state gate.
const CURRENT_ITEM_STATE_OFFSET: usize = 0x80;
/// Offset of the object pointer within the collection handle.
const COLLECTION_OBJECT_OFFSET: usize = 0x04;
/// Vtable byte offset selected by `FUN_081d0e00`.
const CURRENT_ITEM_METHOD_OFFSET: usize = 0x40;

/// Signature of the collection's vtable slot +0x40 method.
type CurrentItemMethod = unsafe extern "C" fn(*mut u8) -> *const u32;

/// Models the unported `FUN_081d0e00` tail target exactly.
unsafe extern "C" fn collection_current_item_word_dispatch(collection: *mut u8) -> u32 {
    let collection_object =
        (collection.add(COLLECTION_OBJECT_OFFSET) as *const *mut u8).read();
    let vtable = (collection_object as *const *const u8).read();
    let method = (vtable.add(CURRENT_ITEM_METHOD_OFFSET) as *const CurrentItemMethod).read_unaligned();
    method(collection.add(COLLECTION_OBJECT_OFFSET)).read()
}

/// Indirection for the unported collection slot-16 accessor.
///
/// The volatile load in [`ui_collection_current_item_word`] keeps this seam
/// replaceable when the port is linked into a firmware payload.
pub static mut COLLECTION_CURRENT_ITEM_WORD_DISPATCH: unsafe extern "C" fn(*mut u8) -> u32 =
    collection_current_item_word_dispatch;

/// Returns the current collection item's opaque word when the owner admits it.
///
/// # Safety
///
/// `owner` must be readable through +0x80. If its item count is nonzero and
/// its state is nonnegative, its embedded collection at +0x2c must satisfy
/// the slot-16 accessor's unchecked pointer requirements; stock ARM has no
/// further NULL guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_collection_current_item_word(owner: *mut u8) -> u32 {
    let item_count = (owner.add(ITEM_COUNT_OFFSET) as *const u32).read();
    let state = (owner.add(CURRENT_ITEM_STATE_OFFSET) as *const i32).read();
    if item_count != 0 && state >= 0 {
        let dispatch =
            core::ptr::read_volatile(core::ptr::addr_of!(COLLECTION_CURRENT_ITEM_WORD_DISPATCH));
        dispatch(owner.add(COLLECTION_HANDLE_OFFSET))
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());

    struct DispatchGuard;

    impl Drop for DispatchGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(COLLECTION_CURRENT_ITEM_WORD_DISPATCH)
                    .write_volatile(collection_current_item_word_dispatch);
            }
        }
    }

    static mut MOCK_COLLECTION: *mut u8 = core::ptr::null_mut();
    static mut MOCK_CALLS: u32 = 0;
    static mut MOCK_RESULT: u32 = 0;

    unsafe extern "C" fn recording_dispatch(collection: *mut u8) -> u32 {
        MOCK_COLLECTION = collection;
        MOCK_CALLS += 1;
        MOCK_RESULT
    }

    unsafe fn install_mock(result: u32) {
        MOCK_COLLECTION = core::ptr::null_mut();
        MOCK_CALLS = 0;
        MOCK_RESULT = result;
        core::ptr::addr_of_mut!(COLLECTION_CURRENT_ITEM_WORD_DISPATCH)
            .write_volatile(recording_dispatch);
    }

    #[repr(C)]
    struct OwnerFixture {
        before_collection: [u32; 11],
        collection_handle: [u32; 2],
        item_count: u32,
        between_count_and_state: [u32; 18],
        current_item_state: i32,
    }

    const _: [u8; COLLECTION_HANDLE_OFFSET] =
        [0; core::mem::offset_of!(OwnerFixture, collection_handle)];
    const _: [u8; ITEM_COUNT_OFFSET] = [0; core::mem::offset_of!(OwnerFixture, item_count)];
    const _: [u8; CURRENT_ITEM_STATE_OFFSET] =
        [0; core::mem::offset_of!(OwnerFixture, current_item_state)];

    impl OwnerFixture {
        fn new(item_count: u32, current_item_state: i32) -> Self {
            Self {
                before_collection: [0; 11],
                collection_handle: [0; 2],
                item_count,
                between_count_and_state: [0; 18],
                current_item_state,
            }
        }
    }

    #[test]
    fn zero_item_count_short_circuits_before_dispatch() {
        let _lock = DISPATCH_LOCK.lock();
        let _restore = DispatchGuard;
        let mut owner = OwnerFixture::new(0, 0);
        unsafe {
            install_mock(0x1234_5678);
            assert_eq!(ui_collection_current_item_word((&mut owner as *mut OwnerFixture).cast()), 0);
            assert_eq!(MOCK_CALLS, 0);
        }
    }

    #[test]
    fn negative_state_short_circuits_before_dispatch() {
        let _lock = DISPATCH_LOCK.lock();
        let _restore = DispatchGuard;
        let mut owner = OwnerFixture::new(1, -1);
        unsafe {
            install_mock(0x1234_5678);
            assert_eq!(ui_collection_current_item_word((&mut owner as *mut OwnerFixture).cast()), 0);
            assert_eq!(MOCK_CALLS, 0);
        }
    }

    #[test]
    fn nonnegative_state_dispatches_embedded_collection_and_returns_its_word() {
        let _lock = DISPATCH_LOCK.lock();
        let _restore = DispatchGuard;
        let mut owner = OwnerFixture::new(7, 0);
        unsafe {
            install_mock(0xc000_0042);
            let owner_ptr = (&mut owner as *mut OwnerFixture).cast::<u8>();
            assert_eq!(ui_collection_current_item_word(owner_ptr), 0xc000_0042);
            assert_eq!(MOCK_CALLS, 1);
            assert_eq!(MOCK_COLLECTION, owner_ptr.add(COLLECTION_HANDLE_OFFSET));
        }
    }
}
