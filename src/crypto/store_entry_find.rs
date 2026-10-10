//! Store entry lookup — `FUN_0806fbf4` @ `0x0806fbf4`.
//! True extent [0x0806fbf4, 0x0806fca4): 176 bytes, ending in POP;
//! the next function starts with PUSH {r3,lr}. Six plain outgoing BLs,
//! zero predicated BLs; two plain incoming BLs (0x080703b4, 0x08070494).
//!
//! Find the first provider-table match. For kinds other than 1, return it
//! directly. For kind 1, scan forward within the comparator-equal run until
//! resource_digest_compare returns zero; stop at a different group or the
//! signed count boundary. Reload the key after comparison, as retailOS does.
//!
//! Deviations: unported comparator 0x08093830 is called at its verified
//! address on device and through an explicit host seam. Host provider words
//! are pointer-sized, matching namespace_provider_find's existing model;
//! target count/entry calls use canonical accessors. Only r0 is a return
//! value: Ghidra's u64 signature mistakes a scratch stack POP into r1 for
//! a second result word. No behavioral deviations on target.

use crate::cxx::object_flags::namespace_provider_find;
use crate::app::resource_digest_compare::resource_digest_compare;

#[repr(C)]
pub struct StoreEntry {
    pub kind: u32,
    pub value: *mut u8,
}

pub type EntryCompare = unsafe extern "C" fn(*const *mut StoreEntry, *mut *mut StoreEntry) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_compare(_: *const *mut StoreEntry, _: *mut *mut StoreEntry) -> i32 {
    panic!("install store entry comparator seam at 0x08093830")
}
#[cfg(not(target_os = "none"))]
pub static mut STORE_ENTRY_COMPARE: EntryCompare = missing_compare;

#[inline(always)]
unsafe fn entry_at(entries: *mut usize, index: i32) -> *mut StoreEntry {
    #[cfg(target_os = "none")]
    { crate::cxx::object_flags::namespace_provider_at(entries.cast(), index as u32) as *mut StoreEntry }
    #[cfg(not(target_os = "none"))]
    { (entries.add(1).read_volatile() as *const usize).wrapping_add(index as u32 as usize).read_volatile() as *mut StoreEntry }
}

/// # Safety
/// Entries must satisfy the provider-table contract. Key and every visited
/// entry must be valid; kind-1 values must be full resource dispatcher states.
/// The comparator may update the key slot to another valid entry. Host seam
/// installation must not race with calls.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn crypto_store_entry_find(entries: *mut usize, mut key: *mut StoreEntry) -> *mut StoreEntry {
    let mut index = namespace_provider_find(entries, key as usize);
    if index == -1 { return core::ptr::null_mut(); }
    if (*key).kind != 1 { return entry_at(entries, index); }
    #[cfg(target_os = "none")]
    let compare: EntryCompare = core::mem::transmute(0x0809_3830usize);
    #[cfg(not(target_os = "none"))]
    let compare = STORE_ENTRY_COMPARE;
    loop {
        #[cfg(target_os = "none")]
        let count = crate::cxx::object_flags::namespace_provider_count(entries.cast());
        #[cfg(not(target_os = "none"))]
        let count = entries.read_volatile() as i32;
        if count <= index { return core::ptr::null_mut(); }
        let entry = entry_at(entries, index);
        if compare(&entry, &mut key) != 0 { return core::ptr::null_mut(); }
        if (*key).kind != 1 || resource_digest_compare((*entry).value, (*key).value) == 0 {
            return entry;
        }
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn group(left: *const *mut StoreEntry, right: *mut *mut StoreEntry) -> i32 {
        ((**left).kind as i32).wrapping_sub((**right).kind as i32)
    }
    extern "C" fn table_group(left: *const u8, right: *const u8) -> i32 {
        unsafe { group(left.cast(), right as *mut *mut StoreEntry) }
    }

    #[test]
    fn duplicate_run_digest_selection_and_boundaries() {
        unsafe {
            STORE_ENTRY_COMPARE = group;
            let mut a = [0u32; 21];
            let mut b = [0u32; 21];
            let mut query = [0u32; 21];
            a[9] = 0x100; b[9] = 0x100; query[9] = 0x100;
            a[15] = 1; b[19] = 0x02000000; query[19] = 0x02000000;
            let mut first = StoreEntry { kind: 1, value: a.as_mut_ptr().cast() };
            let mut second = StoreEntry { kind: 1, value: b.as_mut_ptr().cast() };
            let mut next = StoreEntry { kind: 2, value: core::ptr::null_mut() };
            let mut key = StoreEntry { kind: 1, value: query.as_mut_ptr().cast() };
            let mut table = [&mut first as *mut StoreEntry as usize, &mut second as *mut StoreEntry as usize, &mut next as *mut StoreEntry as usize];
            let mut providers = [3usize, table.as_mut_ptr() as usize, 1, 3, table_group as *const () as usize];
            assert_eq!(crypto_store_entry_find(providers.as_mut_ptr(), &mut key), &mut second as *mut _);
            query[19] = 0;
            assert!(crypto_store_entry_find(providers.as_mut_ptr(), &mut key).is_null());
            providers[0] = 2;
            assert!(crypto_store_entry_find(providers.as_mut_ptr(), &mut key).is_null());
            query[15] = 1;
            assert_eq!(crypto_store_entry_find(providers.as_mut_ptr(), &mut key), &mut first as *mut _);
            providers[0] = 3;
            assert_eq!(crypto_store_entry_find(providers.as_mut_ptr(), &mut next), &mut next as *mut _);
            key.kind = 3;
            assert!(crypto_store_entry_find(providers.as_mut_ptr(), &mut key).is_null());
            assert!(crypto_store_entry_find(core::ptr::null_mut(), core::ptr::null_mut()).is_null());
            providers[0] = 0;
            assert!(crypto_store_entry_find(providers.as_mut_ptr(), &mut key).is_null());
        }
    }
}
