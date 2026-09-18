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
//! Otherwise return zero. The tail target is
//! [`crate::collection_item_word_dispatch`], which pre-decrements its
//! argument by four bytes, invokes the recovered object's vtable slot `+0x40`,
//! and dereferences the returned word pointer.
//!
//! # Deliberate deviation
//!
//! The collection item's concrete type is not established, so this accessor
//! deliberately names only the returned word rather than inventing an item
//! identity.

/// Offset of the embedded collection handle.
const COLLECTION_HANDLE_OFFSET: usize = 0x2c;
/// Offset of the owner's item count.
const ITEM_COUNT_OFFSET: usize = 0x34;
/// Offset of the signed state gate.
const CURRENT_ITEM_STATE_OFFSET: usize = 0x80;

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
        crate::cxx::collection_item_word_dispatch::collection_item_word_dispatch(
            owner.add(COLLECTION_HANDLE_OFFSET),
            state as u32,
        )
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

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
        let mut owner = OwnerFixture::new(0, 0);
        assert_eq!(
            unsafe { ui_collection_current_item_word((&mut owner as *mut OwnerFixture).cast()) },
            0
        );
    }

    #[test]
    fn negative_state_short_circuits_before_dispatch() {
        let mut owner = OwnerFixture::new(1, -1);
        assert_eq!(
            unsafe { ui_collection_current_item_word((&mut owner as *mut OwnerFixture).cast()) },
            0
        );
    }
}
