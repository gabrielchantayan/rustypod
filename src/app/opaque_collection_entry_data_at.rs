//! Opaque collection entry-data accessor.
//!
//! `opaque_collection_entry_data_at` — original: `FUN_08184cf4` @
//! `0x08184cf4` (20 bytes, `0x08184cf4..0x08184d08`). Raw ARM confirms the
//! next separately linked function begins at `0x08184d08`:
//!
//! ```text
//! 08184cf4  push    {r4,lr}
//! 08184cf8  bl      0x08184f98
//! 08184cfc  cmp     r0,#0
//! 08184d00  ldrne   r0,[r0,#8]
//! 08184d04  pop     {r4,pc}
//! ```
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds exactly six direct
//! call sites — `0x0811dc04`, `0x08185700`, `0x08185760`, `0x0819ee70`,
//! `0x081d0bc4`, and `0x08218660` — all plain unconditional `bl`; there are
//! no predicated calls.
//!
//! # Algorithm
//!
//! Calls the sibling bounds-checking vector-entry helper `FUN_08184f98` with
//! the collection and index. A non-NULL entry contributes its aligned word at
//! `+8`; a NULL entry returns zero. The collection itself is not checked here.
//!
//! # Deliberate deviation
//!
//! `FUN_08184f98` is not ported (and `names.yaml` has no entry for it), so the
//! target calls its verified retail address. Host tests install a recording
//! replacement; only the returned entry's observed three-word prefix is
//! modeled.

use core::ptr;

/// Target-width prefix of an entry returned by `FUN_08184f98`.
#[repr(C)]
pub struct OpaqueCollectionEntry {
    pub opaque_00_to_04: [u32; 2],
    pub data: u32,
}

const _: [u8; 0x08] = [0; core::mem::offset_of!(OpaqueCollectionEntry, data)];
const _: [u8; 0x0c] = [0; core::mem::size_of::<OpaqueCollectionEntry>()];

type CollectionEntryAt = unsafe extern "C" fn(*const u8, u32) -> *const OpaqueCollectionEntry;

const COLLECTION_ENTRY_AT_ADDRESS: usize = 0x0818_4f98;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe extern "C" fn retail_collection_entry_at(
    collection: *const u8,
    index: u32,
) -> *const OpaqueCollectionEntry {
    let entry_at: CollectionEntryAt = core::mem::transmute(COLLECTION_ENTRY_AT_ADDRESS);
    entry_at(collection, index)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_collection_entry_at(
    _collection: *const u8,
    _index: u32,
) -> *const OpaqueCollectionEntry {
    panic!("opaque_collection_entry_data_at requires entry lookup 0x08184f98")
}

#[cfg(target_os = "none")]
static mut COLLECTION_ENTRY_AT: CollectionEntryAt = retail_collection_entry_at;
#[cfg(not(target_os = "none"))]
static mut COLLECTION_ENTRY_AT: CollectionEntryAt = missing_collection_entry_at;

/// Returns the `+8` data word of `collection` entry `index`, or zero when its
/// sibling vector lookup returns NULL.
///
/// Original: `FUN_08184cf4` @ `0x08184cf4` (20 bytes; six plain unconditional
/// `bl` call sites, no predicated calls; binary-scanned). The lookup receives
/// both input words unchanged; the only conditional operation is the entry's
/// aligned `+8` read. No target-side deviations.
///
/// # Safety
///
/// `collection` and `index` must be valid for the installed lookup. If it
/// returns non-NULL, the result must point to an aligned readable
/// [`OpaqueCollectionEntry`].
#[cfg_attr(target_os = "none", link_section = ".text.opaque_collection_entry_data_at")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_collection_entry_data_at(
    collection: *const u8,
    index: u32,
) -> u32 {
    let entry_at = ptr::read_volatile(ptr::addr_of!(COLLECTION_ENTRY_AT));
    let entry = entry_at(collection, index);
    if entry.is_null() {
        0
    } else {
        ptr::addr_of!((*entry).data).read_volatile()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut LAST_CALL: Option<(usize, u32)> = None;
    static mut SELECTED_ENTRY: *const OpaqueCollectionEntry = ptr::null();

    unsafe extern "C" fn record_entry_at(
        collection: *const u8,
        index: u32,
    ) -> *const OpaqueCollectionEntry {
        addr_of_mut!(LAST_CALL).write(Some((collection as usize, index)));
        addr_of!(SELECTED_ENTRY).read_volatile()
    }

    struct SeamGuard {
        _lock: MutexGuard<'static, ()>,
        entry_at: CollectionEntryAt,
    }

    impl SeamGuard {
        fn install(entry: *const OpaqueCollectionEntry) -> Self {
            let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
            unsafe {
                let entry_at = addr_of!(COLLECTION_ENTRY_AT).read_volatile();
                addr_of_mut!(LAST_CALL).write(None);
                addr_of_mut!(SELECTED_ENTRY).write_volatile(entry);
                addr_of_mut!(COLLECTION_ENTRY_AT).write_volatile(record_entry_at);
                Self { _lock: lock, entry_at }
            }
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(COLLECTION_ENTRY_AT).write_volatile(self.entry_at) }
        }
    }

    #[test]
    fn returns_the_selected_entry_data_and_forwards_inputs() {
        let collection = [0xa5u8; 16];
        let entry = OpaqueCollectionEntry {
            opaque_00_to_04: [0x1111_2222, 0x3333_4444],
            data: 0x5566_7788,
        };
        let _seam = SeamGuard::install(addr_of!(entry));

        assert_eq!(
            unsafe { opaque_collection_entry_data_at(collection.as_ptr(), 7) },
            0x5566_7788
        );
        assert_eq!(unsafe { addr_of!(LAST_CALL).read() }, Some((collection.as_ptr() as usize, 7)));
    }

    #[test]
    fn null_entry_returns_zero_after_forwarding_every_index_bit() {
        let _seam = SeamGuard::install(ptr::null());

        assert_eq!(unsafe { opaque_collection_entry_data_at(ptr::null(), u32::MAX) }, 0);
        assert_eq!(unsafe { addr_of!(LAST_CALL).read() }, Some((0, u32::MAX)));
    }
}
