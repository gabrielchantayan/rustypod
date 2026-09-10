//! Opaque keyed-collection indexed accessor.
//!
//! `opaque_keyed_collection_item_at` — original: `FUN_0829e2f8` @
//! `0x0829e2f8` (24 bytes, `0x0829e2f8..0x0829e310`). Raw ARM confirms the
//! next separately entered function begins at `0x0829e310`; there is no
//! literal pool:
//!
//! ```text
//! 0829e2f8  push {r4,lr}
//! 0829e2fc  mov  r4,r2
//! 0829e300  bl   0x0829e310
//! 0829e304  ldr  r0,[r0]
//! 0829e308  ldr  r0,[r0,r4,lsl #2]
//! 0829e30c  pop  {r4,pc}
//! ```
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds exactly ten plain,
//! unconditional `bl` call sites — `0x0817eaf8`, `0x0817ec2c`,
//! `0x0817fb68`, `0x0817fe48`, `0x0817fec0`, `0x0817ff48`, `0x0817ffec`,
//! `0x08180070`, `0x08182280`, and `0x08183650` — and no predicated calls.
//! Callers obtain the same key-selected vector's size with the sibling
//! `FUN_0829e2e0`, then use each returned entry's word at +4 as an object id.
//!
//! # Algorithm
//!
//! The unported selector `FUN_0829e310` receives the collection and selector
//! word, and returns a vector head. This accessor reads that head's `begin`
//! word, then returns the 32-bit entry at `begin + index * 4`. It has no NULL
//! guard, bounds check, selector normalization, or writes.
//!
//! # Deliberate deviation
//!
//! `FUN_0829e310` is not ported (and `names.yaml` contains no port for it), so
//! target builds call it at its verified retail address while host tests swap
//! [`OPAQUE_KEYED_COLLECTION_VECTOR`] with a recording implementation. The
//! selector's concrete identity is not recovered; this module deliberately
//! models only the vector head consumed by this function.

use core::ptr;

/// The two-word vector head returned by the unported selector.
///
/// Both fields are target-width words. `end` is present to preserve the
/// selector result's observed `{begin, end}` head even though this accessor
/// reads only `begin`.
#[repr(C)]
pub struct OpaqueKeyedCollectionVector {
    pub begin: u32,
    pub end: u32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(OpaqueKeyedCollectionVector, begin)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(OpaqueKeyedCollectionVector, end)];
const _: [u8; 0x08] = [0; core::mem::size_of::<OpaqueKeyedCollectionVector>()];

/// ABI of `FUN_0829e310`, the still-unported keyed vector selector.
pub type OpaqueKeyedCollectionVectorSelect = unsafe extern "C" fn(
    collection: *const u8,
    selector: u32,
) -> *const OpaqueKeyedCollectionVector;

/// Firmware load address of the unported vector selector `FUN_0829e310`.
pub const OPAQUE_KEYED_COLLECTION_VECTOR_SELECT_ADDRESS: usize = 0x0829_e310;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_opaque_keyed_collection_vector(
    collection: *const u8,
    selector: u32,
) -> *const OpaqueKeyedCollectionVector {
    let select: OpaqueKeyedCollectionVectorSelect =
        core::mem::transmute(OPAQUE_KEYED_COLLECTION_VECTOR_SELECT_ADDRESS);
    select(collection, selector)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_keyed_collection_vector(
    _collection: *const u8,
    _selector: u32,
) -> *const OpaqueKeyedCollectionVector {
    panic!("opaque_keyed_collection_item_at requires selector 0x0829e310")
}

/// Dispatch seam for the unported `FUN_0829e310` keyed vector selector.
#[cfg(target_os = "none")]
pub static mut OPAQUE_KEYED_COLLECTION_VECTOR: OpaqueKeyedCollectionVectorSelect =
    retail_opaque_keyed_collection_vector;

/// Host-test dispatch seam for the unported keyed vector selector.
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_KEYED_COLLECTION_VECTOR: OpaqueKeyedCollectionVectorSelect =
    missing_opaque_keyed_collection_vector;

/// opaque_keyed_collection_item_at — original: `FUN_0829e2f8` @ `0x0829e2f8`
/// (24 bytes; 10 plain `bl` call sites, no predicated calls; binary-scanned).
///
/// Returns entry `index` from the vector selected by `selector`. The original
/// performs an aligned word load with `index << 2`; invalid collection,
/// selector-result, vector, or index inputs have the same unchecked behavior.
///
/// # Safety
///
/// `collection` and `selector` must be accepted by the installed selector. Its
/// result must point to an aligned [`OpaqueKeyedCollectionVector`] whose
/// `begin` target word names a readable `u32` at `index`.
#[cfg_attr(target_os = "none", link_section = ".text.opaque_keyed_collection_item_at")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_keyed_collection_item_at(
    collection: *const u8,
    selector: u32,
    index: u32,
) -> u32 {
    let select = ptr::read_volatile(ptr::addr_of!(OPAQUE_KEYED_COLLECTION_VECTOR));
    let vector = select(collection, selector);
    let begin = ptr::addr_of!((*vector).begin).read_volatile();
    (begin as usize as *const u32).wrapping_add(index as usize).read_volatile()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    use std::vec::Vec;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static FIXTURE_BASE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::OPAQUE_KEYED_COLLECTION_ITEM_AT, 0x1000).map(|p| p as usize)
    });
    static mut CALLS: Vec<(usize, u32)> = Vec::new();
    static mut SELECTED_VECTOR: *const OpaqueKeyedCollectionVector = ptr::null();

    const VECTOR_WORD: usize = 4;
    const ENTRIES_WORD: usize = 16;

    unsafe extern "C" fn recording_vector_selector(
        collection: *const u8,
        selector: u32,
    ) -> *const OpaqueKeyedCollectionVector {
        (*ptr::addr_of_mut!(CALLS)).push((collection as usize, selector));
        ptr::read_volatile(ptr::addr_of!(SELECTED_VECTOR))
    }

    struct SeamGuard;

    impl SeamGuard {
        fn install(vector: *const OpaqueKeyedCollectionVector) -> Self {
            unsafe {
                ptr::addr_of_mut!(SELECTED_VECTOR).write_volatile(vector);
                ptr::addr_of_mut!(CALLS).write(Vec::new());
                ptr::addr_of_mut!(OPAQUE_KEYED_COLLECTION_VECTOR)
                    .write_volatile(recording_vector_selector);
            }
            SeamGuard
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(OPAQUE_KEYED_COLLECTION_VECTOR)
                    .write_volatile(missing_opaque_keyed_collection_vector);
            }
        }
    }

    fn fixture() -> Option<(*mut u32, *mut OpaqueKeyedCollectionVector)> {
        let base = (*FIXTURE_BASE)? as *mut u32;
        unsafe {
            let entries = base.add(ENTRIES_WORD);
            let vector = base.add(VECTOR_WORD) as *mut OpaqueKeyedCollectionVector;
            ptr::addr_of_mut!((*vector).begin).write(entries as usize as u32);
            ptr::addr_of_mut!((*vector).end).write(entries.add(4) as usize as u32);
            Some((entries, vector))
        }
    }

    #[test]
    fn returns_the_requested_entry_and_forwards_selector() {
        let _lock = SEAM_LOCK.lock();
        let Some((entries, vector)) = fixture() else {
            assert!(note_missing_u32_fixture("app::opaque_keyed_collection_item_at"));
            return;
        };
        let collection = [0u32; 12];
        unsafe {
            entries.add(0).write(0x1111_2222);
            entries.add(1).write(0x3333_4444);
            entries.add(2).write(0x5555_6666);
            let _seam = SeamGuard::install(vector);
            assert_eq!(
                opaque_keyed_collection_item_at(collection.as_ptr() as *const u8, 0x0000_00a5, 2),
                0x5555_6666
            );
        }
        assert_eq!(
            unsafe { (*ptr::addr_of!(CALLS)).clone() },
            std::vec![(collection.as_ptr() as usize, 0x0000_00a5)]
        );
    }

    #[test]
    fn preserves_all_selector_bits_and_reads_index_zero() {
        let _lock = SEAM_LOCK.lock();
        let Some((entries, vector)) = fixture() else {
            assert!(note_missing_u32_fixture("app::opaque_keyed_collection_item_at"));
            return;
        };
        let collection = [0u32; 12];
        unsafe {
            entries.add(0).write(0xdead_beef);
            let _seam = SeamGuard::install(vector);
            assert_eq!(
                opaque_keyed_collection_item_at(collection.as_ptr() as *const u8, 0xfeed_c0de, 0),
                0xdead_beef
            );
        }
        assert_eq!(
            unsafe { (*ptr::addr_of!(CALLS)).clone() },
            std::vec![(collection.as_ptr() as usize, 0xfeed_c0de)]
        );
    }

    #[test]
    fn does_not_consult_end_or_write_the_vector_head() {
        let _lock = SEAM_LOCK.lock();
        let Some((entries, vector)) = fixture() else {
            assert!(note_missing_u32_fixture("app::opaque_keyed_collection_item_at"));
            return;
        };
        unsafe {
            entries.add(3).write(0x7fff_ffff);
            ptr::addr_of_mut!((*vector).end).write(0xffff_fffcu32);
            let before = ptr::read(vector);
            let _seam = SeamGuard::install(vector);
            assert_eq!(opaque_keyed_collection_item_at(ptr::null(), 1, 3), 0x7fff_ffff);
            assert_eq!(ptr::read(vector).begin, before.begin);
            assert_eq!(ptr::read(vector).end, before.end);
        }
    }
}
