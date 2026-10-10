//! Store key index — `FUN_0806fb74` @ `0x0806fb74`.
//! True extent [0x0806fb74, 0x0806fbcc): 88 bytes; next entry PUSH {r4,lr}.
//! One plain outgoing BL to namespace_provider_find, zero predicated BLs.
//! Two plain incoming BLs at 0x0806fbd4 and 0x0806ff74, none predicated.
//!
//! Reject kinds other than 1 and 2 with -1. Build a temporary StoreEntry
//! whose value points to a pointer to an inner object; put the supplied key
//! at inner word 5 for kind 1 or word 2 for kind 2. Return the first matching
//! provider-table index through the canonical namespace_provider_find port.
//!
//! Deviations: omit unused stack padding, leaving unused inner fields
//! uninitialized as in retailOS. Host pointer fields widen consistently with
//! StoreEntry and namespace_provider_find; target fields remain four bytes.

use core::mem::MaybeUninit;
use crate::crypto::store_entry_find::StoreEntry;
use crate::cxx::object_flags::namespace_provider_find;

/// # Safety
/// Entries must satisfy namespace_provider_find's contract. Its comparator
/// must only inspect kind and the selected nested key (retail 0x08093830),
/// and must not retain the temporary lookup object. Key must be valid for
/// that comparator. Unsupported kinds do not access entries or key.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn crypto_store_key_index(entries: *mut usize, kind: u32, key: *mut u8) -> i32 {
    let key_word = match kind { 1 => 5, 2 => 2, _ => return -1 };
    let mut inner = [MaybeUninit::<usize>::uninit(); 6];
    inner[key_word].write(key as usize);
    let mut inner_pointer = inner.as_mut_ptr();
    let entry = StoreEntry {
        kind,
        value: core::ptr::addr_of_mut!(inner_pointer).cast(),
    };
    namespace_provider_find(entries, core::ptr::addr_of!(entry) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn compare(left: *const u8, right: *const u8) -> i32 {
        let a = &*(*(left as *const usize) as *const StoreEntry);
        let b = &*(*(right as *const usize) as *const StoreEntry);
        if a.kind != b.kind { return if a.kind < b.kind { -1 } else { 1 }; }
        let word = if a.kind == 1 { 5 } else { 2 };
        let a_key = (*(a.value as *const *const usize)).add(word).read();
        let b_key = (*(b.value as *const *const usize)).add(word).read();
        if a_key < b_key { -1 } else if a_key > b_key { 1 } else { 0 }
    }

    #[test]
    fn nested_keys_first_duplicate_misses_and_kind_boundaries() {
        unsafe {
            let mut inner = [[0usize; 6]; 5];
            inner[0][5] = 10; inner[1][5] = 20; inner[2][5] = 20;
            inner[3][2] = 10; inner[4][2] = 30;
            let mut pointers = inner.map(|_| core::ptr::null_mut::<usize>());
            for i in 0..5 { pointers[i] = inner[i].as_mut_ptr(); }
            let mut entries = core::array::from_fn::<_, 5, _>(|i| StoreEntry {
                kind: if i < 3 { 1 } else { 2 },
                value: core::ptr::addr_of_mut!(pointers[i]).cast(),
            });
            let mut table = entries.each_mut().map(|entry| entry as *mut StoreEntry as usize);
            let mut provider = [5usize, table.as_mut_ptr() as usize, 1, 5, compare as *const () as usize];
            for (kind, key, expected) in [(1, 10, 0), (1, 20, 1), (2, 10, 3), (2, 30, 4),
                (1, 0, -1), (1, 15, -1), (2, 20, -1), (2, usize::MAX, -1)] {
                assert_eq!(crypto_store_key_index(provider.as_mut_ptr(), kind, key as *mut u8), expected);
            }
            provider[0] = 0;
            assert_eq!(crypto_store_key_index(provider.as_mut_ptr(), 1, 10usize as *mut u8), -1);
            for kind in [0, 3, u32::MAX] {
                assert_eq!(crypto_store_key_index(core::ptr::null_mut(), kind, core::ptr::null_mut()), -1);
            }
            assert_eq!(crypto_store_key_index(core::ptr::null_mut(), 2, core::ptr::null_mut()), -1);
        }
    }
}
