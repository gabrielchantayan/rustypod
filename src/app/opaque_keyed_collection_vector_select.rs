//! Opaque keyed-collection vector selector.
//!
//! `opaque_keyed_collection_vector_select` — original: `FUN_0829e310` @
//! `0x0829e310` (76 bytes, `0x0829e310..0x0829e35c`; **3 plain `bl` call
//! sites and 0 predicated `bl` call sites**). Raw ARM establishes the next
//! real function boundary at `0x0829e35c`:
//!
//! ```text
//! 0829e310  push {r0,r1,r4,r5,lr}
//! 0829e320  bl   0x083d7248
//! 0829e338  bl   0x083d7248
//! 0829e35c  push {r3,lr}
//! ```
//!
//! # Algorithm
//!
//! Looks up `selector` in the opaque ordered collection rooted at
//! `collection + 0x1c`. If that lookup returns the collection's sentinel word
//! at +0x2c, it performs the same lookup for selector one. It returns the
//! selected lookup result plus 0x14. The lookup helper at `0x083d7248` is not
//! ported; its concrete type is unrecovered, so it remains a single explicit
//! boundary.
//!
//! # Deliberate deviation
//!
//! The retail helper receives its selector by stack address. Rust passes a
//! pointer to a local `u32`, preserving the pointed-to value and allowing the
//! helper boundary to be host-tested; no concrete collection layout is claimed.

use core::ptr;

use super::opaque_keyed_collection_item_at::OpaqueKeyedCollectionVector;

const OPAQUE_KEYED_COLLECTION_LOOKUP_ADDRESS: usize = 0x083d_7248;

type OpaqueKeyedCollectionLookup = unsafe extern "C" fn(*const u8, *const u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_opaque_keyed_collection_lookup(
    collection_tree: *const u8,
    selector: *const u32,
) -> u32 {
    let lookup: OpaqueKeyedCollectionLookup = core::mem::transmute(OPAQUE_KEYED_COLLECTION_LOOKUP_ADDRESS);
    lookup(collection_tree, selector)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_keyed_collection_lookup(
    _collection_tree: *const u8,
    _selector: *const u32,
) -> u32 {
    panic!("opaque_keyed_collection_vector_select requires lookup 0x083d7248")
}

#[cfg(target_os = "none")]
static mut OPAQUE_KEYED_COLLECTION_LOOKUP: OpaqueKeyedCollectionLookup =
    retail_opaque_keyed_collection_lookup;

#[cfg(not(target_os = "none"))]
static mut OPAQUE_KEYED_COLLECTION_LOOKUP: OpaqueKeyedCollectionLookup =
    missing_opaque_keyed_collection_lookup;

/// Selects a keyed collection vector — original: `FUN_0829e310` @ `0x0829e310`
/// (76 bytes; 3 plain `bl` call sites, no predicated `bl` call sites).
///
/// # Safety
///
/// `collection` must name an object with readable target words at +0x1c and
/// +0x2c. The installed lookup must accept the tree at +0x1c and return a
/// target address whose +0x14 field is an [`OpaqueKeyedCollectionVector`].
#[cfg_attr(target_os = "none", link_section = ".text.opaque_keyed_collection_vector_select")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_keyed_collection_vector_select(
    collection: *const u8,
    selector: u32,
) -> *const OpaqueKeyedCollectionVector {
    let lookup = ptr::read_volatile(ptr::addr_of!(OPAQUE_KEYED_COLLECTION_LOOKUP));
    let tree = collection.wrapping_add(0x1c);
    let result = lookup(tree, ptr::addr_of!(selector));
    let selected = if result == collection.wrapping_add(0x2c).cast::<u32>().read_volatile() {
        let fallback = 1u32;
        lookup(tree, ptr::addr_of!(fallback))
    } else {
        result
    };
    selected.wrapping_add(0x14) as usize as *const OpaqueKeyedCollectionVector
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::OPAQUE_KEYED_COLLECTION_VECTOR_TEST_LOCK;

    static mut RESULTS: [u32; 2] = [0; 2];
    static mut KEYS: [u32; 2] = [0; 2];
    static mut CALLS: usize = 0;

    unsafe extern "C" fn recording_lookup(_tree: *const u8, selector: *const u32) -> u32 {
        let call = ptr::addr_of!(CALLS).read();
        ptr::addr_of_mut!(KEYS).cast::<u32>().add(call).write(selector.read());
        ptr::addr_of_mut!(CALLS).write(call + 1);
        ptr::addr_of!(RESULTS).cast::<u32>().add(call).read()
    }

    struct LookupGuard(OpaqueKeyedCollectionLookup);
    impl Drop for LookupGuard {
        fn drop(&mut self) { unsafe { ptr::addr_of_mut!(OPAQUE_KEYED_COLLECTION_LOOKUP).write_volatile(self.0) } }
    }

    unsafe fn install(results: [u32; 2]) -> LookupGuard {
        ptr::addr_of_mut!(RESULTS).write(results);
        ptr::addr_of_mut!(KEYS).write([0; 2]);
        ptr::addr_of_mut!(CALLS).write(0);
        let seam = ptr::addr_of_mut!(OPAQUE_KEYED_COLLECTION_LOOKUP);
        let previous = seam.read_volatile();
        seam.write_volatile(recording_lookup);
        LookupGuard(previous)
    }

    #[test]
    fn returns_first_lookup_vector_without_fallback() {
        let _lock = OPAQUE_KEYED_COLLECTION_VECTOR_TEST_LOCK.lock();
        let collection = [0u32; 12];
        unsafe {
            let _guard = install([0x2000, 0]);
            assert_eq!(opaque_keyed_collection_vector_select(collection.as_ptr().cast(), 0xfeed_c0de) as usize, 0x2014);
            assert_eq!(ptr::addr_of!(CALLS).read(), 1);
            assert_eq!(ptr::addr_of!(KEYS).read(), [0xfeed_c0de, 0]);
        }
    }

    #[test]
    fn retries_with_one_when_first_lookup_returns_sentinel() {
        let _lock = OPAQUE_KEYED_COLLECTION_VECTOR_TEST_LOCK.lock();
        let mut collection = [0u32; 12];
        collection[11] = 0x1000;
        unsafe {
            let _guard = install([0x1000, 0x3000]);
            assert_eq!(opaque_keyed_collection_vector_select(collection.as_ptr().cast(), 0) as usize, 0x3014);
            assert_eq!(ptr::addr_of!(CALLS).read(), 2);
            assert_eq!(ptr::addr_of!(KEYS).read(), [0, 1]);
        }
    }
}
