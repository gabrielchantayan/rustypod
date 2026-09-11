//! First collection-item bounds for a UI element.
//!
//! `ui_element_copy_first_collection_item_bounds` — original:
//! `FUN_08146c94` @ **0x08146c94**, 96 bytes
//! (`0x08146c94..0x08146cf4`; the separately linked next function begins at
//! `0x08146cf4`). Raw whole-image ARM B/BL decoding finds exactly 10 direct
//! call sites, all unconditional `bl` instructions; there are no predicated
//! calls or tail branches to this entry.
//!
//! # Algorithm
//!
//! Clear `out`, construct a collection iterator over the element's embedded
//! collection at +0xa8 with start position -2 (before first), then advance it
//! once. If the returned item pointer is non-NULL, copy its bounds rectangle
//! at +0x80 to `out`. Finally, release the iterator state. The collection and
//! its item type remain opaque: only their recovered placement and the item's
//! shared UI bounds prefix are modeled.
//!
//! # Deliberate deviation
//!
//! The raw ARM leaves its one-word item temporary uninitialized before calling
//! `iterator_state_next`; an empty fetch that does not write its out pointer
//! would therefore cause an indeterminate pointer read. Rust initializes that
//! temporary to NULL, preserving the function's cleared output for an empty
//! collection instead of making a safe port invoke undefined behavior.

use core::mem::{offset_of, size_of};
use core::ptr;

use crate::app::vtable_set::{iterator_state_cleanup, iterator_state_construct, iterator_state_next};
use crate::ui::rect::Rect;

#[repr(C)]
struct ElementCollectionFields {
    _before_collection: [u8; 0xa8],
    collection: OpaqueCollection,
}

#[repr(C)]
struct OpaqueCollection {
    _words: [u32; 4],
}

#[repr(C)]
struct CollectionItemBounds {
    _before_bounds: [u8; 0x80],
    bounds: Rect,
}

const _: [u8; 0xa8] = [0; offset_of!(ElementCollectionFields, collection)];
const _: [u8; 0x90] = [0; size_of::<CollectionItemBounds>()];
const _: [u8; 0x80] = [0; offset_of!(CollectionItemBounds, bounds)];

/// Copies the first item in `element`'s embedded collection to `out`.
///
/// # Safety
///
/// `element` must hold a collection at +0xa8 acceptable to the iterator
/// family, `out` must name 16 writable bytes, and a non-NULL item returned by
/// that collection must hold a readable [`Rect`] at +0x80. The retail body
/// performs no validation of any of these conditions.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_copy_first_collection_item_bounds(
    element: *mut u8,
    out: *mut Rect,
) {
    let fields = element.cast::<ElementCollectionFields>();
    let mut iterator = [0u32; 5];
    let mut item = ptr::null_mut::<u8>();

    ptr::write(out, Rect::default());
    iterator_state_construct(
        iterator.as_mut_ptr(),
        ptr::addr_of_mut!((*fields).collection).cast(),
        -2,
    );
    iterator_state_next(iterator.as_mut_ptr(), ptr::addr_of_mut!(item).cast());
    if !item.is_null() {
        let item = item.cast::<CollectionItemBounds>();
        ptr::write(out, ptr::addr_of!((*item).bounds).read());
    }
    iterator_state_cleanup(iterator.as_mut_ptr());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::vtable_set::{tests::{SLOT_TEST_LOCK, SlotGuard}, ITERATOR_STATE_FETCH};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    static mut FETCH_ITEM: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn fetch_item(_state: *mut u32, out: *mut u8) -> u32 {
        out.cast::<*mut u8>().write(FETCH_ITEM);
        1
    }

    unsafe extern "C" fn fetch_without_output(_state: *mut u32, _out: *mut u8) -> u32 {
        0
    }

    #[test]
    fn copies_the_first_item_bounds_and_keeps_empty_output_clear() {
        let _lock = SLOT_TEST_LOCK.lock();
        let _restore = SlotGuard;
        let Some(element) = try_map_u32_slab(hints::UI_FIRST_COLLECTION_ITEM_BOUNDS, size_of::<ElementCollectionFields>()) else {
            note_missing_u32_fixture("ui/first_collection_item_bounds");
            return;
        };
        let mut item = CollectionItemBounds {
            _before_bounds: [0; 0x80],
            bounds: Rect { top: -4, left: 10, bottom: 26, right: 44 },
        };
        let mut out = Rect { top: 1, left: 2, bottom: 3, right: 4 };

        unsafe {
            ptr::write_bytes(element, 0, size_of::<ElementCollectionFields>());
            FETCH_ITEM = (&mut item as *mut CollectionItemBounds).cast();
            ptr::addr_of_mut!(ITERATOR_STATE_FETCH).write_volatile(fetch_item);
            ui_element_copy_first_collection_item_bounds(element, &mut out);
            assert_eq!(out, item.bounds, "the first returned item supplies all four bounds words");

            out = Rect { top: -1, left: -2, bottom: -3, right: -4 };
            ptr::addr_of_mut!(ITERATOR_STATE_FETCH).write_volatile(fetch_without_output);
            ui_element_copy_first_collection_item_bounds(element, &mut out);
            assert_eq!(out, Rect::default(), "an empty traversal retains the initial cleared rectangle");
        }
    }
}
