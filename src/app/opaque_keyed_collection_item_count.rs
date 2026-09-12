//! Opaque keyed-collection item-count accessor.
//!
//! `opaque_keyed_collection_item_count` — original: `FUN_0829e2e0` @
//! `0x0829e2e0` (24 bytes, `0x0829e2e0..0x0829e2f8`). Raw ARM confirms the
//! next separately entered function begins at `0x0829e2f8`; there is no
//! literal pool:
//!
//! ```text
//! 0829e2e0  push {r4,lr}
//! 0829e2e4  bl   0x0829e310
//! 0829e2e8  ldm  r0,{r0,r1}
//! 0829e2ec  sub  r0,r1,r0
//! 0829e2f0  asr  r0,r0,#2
//! 0829e2f4  pop  {r4,pc}
//! ```
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds exactly eight plain,
//! unconditional `bl` call sites — `0x0817eadc`, `0x0817ec04`, `0x0817fb40`,
//! `0x0817fb50`, `0x0817fe1c`, `0x0817fe2c`, `0x0818225c`, and `0x081836dc`
//! — and no predicated calls. No 32-bit data word in `osos.dec` equals this
//! function's address.
//!
//! # Algorithm
//!
//! The unported selector `FUN_0829e310` receives the collection and selector
//! word, and returns a vector head. This accessor returns the arithmetic-right
//! shift by two of `end - begin`: the signed, target-width element count. It
//! has no NULL guard, selector normalization, validation, or writes.
//!
//! # Deliberate deviation
//!
//! `FUN_0829e310` remains unported, so this function reuses its sibling
//! accessor's existing `OPAQUE_KEYED_COLLECTION_VECTOR` dispatch seam. Target
//! builds reach the verified retail address; host tests install a recording
//! selector. No concrete collection or selector identity is claimed.

use core::ptr;

use super::opaque_keyed_collection_item_at::OPAQUE_KEYED_COLLECTION_VECTOR;
#[cfg(test)]
use super::opaque_keyed_collection_item_at::OpaqueKeyedCollectionVector;

/// opaque_keyed_collection_item_count — original: `FUN_0829e2e0` @
/// `0x0829e2e0` (24 bytes; 8 plain `bl` call sites, no predicated calls;
/// binary-scanned).
///
/// Selects the collection vector, then returns the target-width arithmetic
/// right shift of `(end - begin)` by two. The original performs two aligned
/// word loads and has no NULL guard, bounds check, or writes.
///
/// # Safety
///
/// `collection` and `selector` must be accepted by the installed selector. Its
/// result must point to an aligned [`OpaqueKeyedCollectionVector`].
#[cfg_attr(target_os = "none", link_section = ".text.opaque_keyed_collection_item_count")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_keyed_collection_item_count(
    collection: *const u8,
    selector: u32,
) -> u32 {
    let select = ptr::read_volatile(ptr::addr_of!(OPAQUE_KEYED_COLLECTION_VECTOR));
    let vector = select(collection, selector);
    let begin = ptr::addr_of!((*vector).begin).read_volatile();
    let end = ptr::addr_of!((*vector).end).read_volatile();
    ((end.wrapping_sub(begin) as i32) >> 2) as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::opaque_keyed_collection_item_at::OpaqueKeyedCollectionVectorSelect;
    use crate::testing::{
        hints, note_missing_u32_fixture, try_map_u32_slab,
        OPAQUE_KEYED_COLLECTION_VECTOR_TEST_LOCK,
    };
    use core::ptr;
    use std::sync::LazyLock;

    static FIXTURE_BASE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::OPAQUE_KEYED_COLLECTION_ITEM_COUNT, 0x1000).map(|p| p as usize)
    });
    static mut CALL: Option<(usize, u32)> = None;
    static mut SELECTED_VECTOR: *const OpaqueKeyedCollectionVector = ptr::null();

    unsafe extern "C" fn recording_vector_selector(
        collection: *const u8,
        selector: u32,
    ) -> *const OpaqueKeyedCollectionVector {
        ptr::addr_of_mut!(CALL).write(Some((collection as usize, selector)));
        ptr::read_volatile(ptr::addr_of!(SELECTED_VECTOR))
    }

    struct SeamGuard {
        previous: OpaqueKeyedCollectionVectorSelect,
    }

    impl SeamGuard {
        unsafe fn install(vector: *const OpaqueKeyedCollectionVector) -> Self {
            ptr::addr_of_mut!(SELECTED_VECTOR).write_volatile(vector);
            ptr::addr_of_mut!(CALL).write(None);
            let seam = ptr::addr_of_mut!(OPAQUE_KEYED_COLLECTION_VECTOR);
            let previous = seam.read_volatile();
            seam.write_volatile(recording_vector_selector);
            Self { previous }
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(OPAQUE_KEYED_COLLECTION_VECTOR).write_volatile(self.previous);
            }
        }
    }

    fn fixture() -> Option<*mut OpaqueKeyedCollectionVector> {
        let base = (*FIXTURE_BASE)? as *mut u32;
        Some(unsafe { base.add(4) as *mut OpaqueKeyedCollectionVector })
    }

    #[test]
    fn returns_vector_element_count_and_forwards_selector_unchanged() {
        let _lock = OPAQUE_KEYED_COLLECTION_VECTOR_TEST_LOCK.lock();
        let Some(vector) = fixture() else {
            assert!(note_missing_u32_fixture("app::opaque_keyed_collection_item_count"));
            return;
        };
        let collection = [0u32; 4];
        unsafe {
            ptr::addr_of_mut!((*vector).begin).write(0x1000_0000);
            ptr::addr_of_mut!((*vector).end).write(0x1000_0014);
            let _seam = SeamGuard::install(vector);
            assert_eq!(
                opaque_keyed_collection_item_count(collection.as_ptr() as *const u8, 0xfeed_c0de),
                5
            );
            assert_eq!(ptr::addr_of!(CALL).read(), Some((collection.as_ptr() as usize, 0xfeed_c0de)));
        }
    }

    #[test]
    fn preserves_signed_underflow_from_the_arm_arithmetic_shift() {
        let _lock = OPAQUE_KEYED_COLLECTION_VECTOR_TEST_LOCK.lock();
        let Some(vector) = fixture() else {
            assert!(note_missing_u32_fixture("app::opaque_keyed_collection_item_count"));
            return;
        };
        unsafe {
            ptr::addr_of_mut!((*vector).begin).write(4);
            ptr::addr_of_mut!((*vector).end).write(0);
            let _seam = SeamGuard::install(vector);
            assert_eq!(opaque_keyed_collection_item_count(ptr::null(), 0), u32::MAX);

            ptr::addr_of_mut!((*vector).begin).write(0x8000_0000);
            ptr::addr_of_mut!((*vector).end).write(0);
            assert_eq!(opaque_keyed_collection_item_count(ptr::null(), u32::MAX), 0xe000_0000);
        }
    }

    #[test]
    fn reads_both_vector_words_without_writing_them() {
        let _lock = OPAQUE_KEYED_COLLECTION_VECTOR_TEST_LOCK.lock();
        let Some(vector) = fixture() else {
            assert!(note_missing_u32_fixture("app::opaque_keyed_collection_item_count"));
            return;
        };
        unsafe {
            ptr::addr_of_mut!((*vector).begin).write(0x2345_6780);
            ptr::addr_of_mut!((*vector).end).write(0x2345_6780);
            let before = ptr::read(vector);
            let _seam = SeamGuard::install(vector);
            assert_eq!(opaque_keyed_collection_item_count(ptr::null(), 1), 0);
            assert_eq!(ptr::read(vector).begin, before.begin);
            assert_eq!(ptr::read(vector).end, before.end);
        }
    }
}
