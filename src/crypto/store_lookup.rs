//! Tagged certificate-store lookup — FUN_08070574 @ 0x08070574, 168 bytes.
//! Next real entry: 0x0807061c. Raw A32 scan: two incoming plain BLs
//! (0x0806fee8, 0x080ebc98), five outgoing plain BLs, no predicated BLs.
//! Search the cached tagged entries first, then query providers starting at
//! the saved signed cursor. Negative results save that result as the cursor;
//! success/exhaustion reset it. Copy a successful two-word entry and retain it.
//! Deliberate deviations: repr(C) owner pointers widen on hosts; tagged entries
//! remain two u32 words. Unported cache search and provider dispatch retain
//! their verified firmware addresses; host callers must install those seams.

use crate::cxx::object_flags::{namespace_provider_at, namespace_provider_count};
use crate::crypto::tagged_reference_retain::crypto_tagged_reference_retain;
use core::mem::MaybeUninit;

#[repr(C)]
pub struct StoreOwner {
    pub opaque: *mut u8,
    pub cached_entries: *const u32,
    pub providers: *const u32,
}

#[repr(C)]
pub struct StoreLookup {
    pub owner: *const StoreOwner,
    pub cursor: i32,
}

/// Cache search at 0x0806fbcc forwards all three registers to 0x0806fb74.
pub type CacheSearch = unsafe extern "C" fn(*const u32, u32, u32) -> *const u32;
/// Provider dispatcher at 0x0806f1c8 tail-calls method +0x18 with r0-r3 intact.
pub type ProviderQuery = unsafe extern "C" fn(*const u32, u32, u32, *mut u32) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cache(_: *const u32, _: u32, _: u32) -> *const u32 {
    panic!("install store lookup cache search seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_provider(_: *const u32, _: u32, _: u32, _: *mut u32) -> i32 {
    panic!("install store lookup provider query seam")
}
#[cfg(not(target_os = "none"))]
pub static mut STORE_CACHE_SEARCH: CacheSearch = missing_cache;
#[cfg(not(target_os = "none"))]
pub static mut STORE_PROVIDER_QUERY: ProviderQuery = missing_provider;

/// # Safety
/// The state and owner must be valid, as must provider tables for every signed
/// index visited. Output must hold two writable words. Successful callees must
/// initialize both entry words; kinds 1/2 must reference valid retainable objects.
/// Host seams must be installed without concurrent mutation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn crypto_store_lookup(
    state: *mut StoreLookup, kind: u32, key: u32, output: *mut u32,
) -> i32 {
    #[cfg(target_os = "none")]
    let (cache_search, provider_query): (CacheSearch, ProviderQuery) = (
        core::mem::transmute(0x0806_fbccusize), core::mem::transmute(0x0806_f1c8usize),
    );
    #[cfg(not(target_os = "none"))]
    let (cache_search, provider_query) = (STORE_CACHE_SEARCH, STORE_PROVIDER_QUERY);
    let owner = (*state).owner;
    let mut entry = cache_search((*owner).cached_entries, kind, key);
    let mut temporary = MaybeUninit::<[u32; 2]>::uninit();
    if entry.is_null() {
        let mut index = (*state).cursor;
        while namespace_provider_count((*owner).providers) > index {
            let provider = namespace_provider_at((*owner).providers, index as u32);
            let result = provider_query(provider, kind, key, temporary.as_mut_ptr().cast());
            if result < 0 {
                (*state).cursor = result;
                return result;
            }
            if result != 0 {
                entry = temporary.as_ptr().cast();
                break;
            }
            index = index.wrapping_add(1);
        }
        (*state).cursor = 0;
        if entry.is_null() { return 0; }
    }
    output.write(entry.read());
    output.add(1).write(entry.add(1).read());
    crypto_tagged_reference_retain(output);
    1
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    unsafe extern "C" fn cache(entries: *const u32, kind: u32, key: u32) -> *const u32 {
        if !entries.is_null() && entries.read() == kind && entries.add(1).read() == key {
            entries.add(2)
        } else { ptr::null() }
    }
    unsafe extern "C" fn query(provider: *const u32, kind: u32, key: u32, out: *mut u32) -> i32 {
        let result = provider.read() as i32;
        if result > 0 && provider.add(1).read() == kind && provider.add(2).read() == key {
            out.write(0); // Unsupported tag: retain must not read the payload pointer.
            out.add(1).write(provider.add(3).read());
            result
        } else if result < 0 { result } else { 0 }
    }

    #[test]
    fn cache_precedence_provider_progress_errors_and_exhaustion() {
        let _guard = LOCK.lock();
        unsafe {
            STORE_CACHE_SEARCH = cache;
            STORE_PROVIDER_QUERY = query;
            let cached = [2, 77, 0, 123];
            let miss = [0, 2, 77, 111];
            let hit = [9, 2, 77, 456];
            let error = [-7i32 as u32, 0, 0, 0];
            let mut table = [miss.as_ptr(), hit.as_ptr(), error.as_ptr()];
            // Accessor's host convention keeps the pointer at target offset +4.
            let mut providers = [0usize; 2];
            let p = providers.as_mut_ptr().cast::<u32>();
            p.write(3);
            ptr::write_unaligned(p.add(1).cast::<*const *const u32>(), table.as_ptr());
            let mut owner = StoreOwner { opaque: ptr::null_mut(), cached_entries: cached.as_ptr(), providers: p };
            let mut state = StoreLookup { owner: &owner, cursor: 2 };
            let mut output = [88, 99];
            assert_eq!(crypto_store_lookup(&mut state, 2, 77, output.as_mut_ptr()), 1);
            assert_eq!(output, [0, 123]);
            assert_eq!(state.cursor, 2); // Cache hits do not reset the cursor.
            owner.cached_entries = ptr::null();
            state.cursor = 0;
            assert_eq!(crypto_store_lookup(&mut state, 2, 77, output.as_mut_ptr()), 1);
            assert_eq!(output, [0, 456]);
            assert_eq!(state.cursor, 0);
            state.cursor = 2;
            output = [88, 99];
            assert_eq!(crypto_store_lookup(&mut state, 2, 77, output.as_mut_ptr()), -7);
            assert_eq!(state.cursor, -7);
            assert_eq!(output, [88, 99]);
            table[2] = miss.as_ptr();
            state.cursor = 1;
            assert_eq!(crypto_store_lookup(&mut state, 1, 77, output.as_mut_ptr()), 0);
            assert_eq!(state.cursor, 0);
            assert_eq!(output, [88, 99]);
            state.cursor = 3;
            assert_eq!(crypto_store_lookup(&mut state, 2, 77, output.as_mut_ptr()), 0);
            assert_eq!(state.cursor, 0);
            owner.providers = ptr::null();
            assert_eq!(crypto_store_lookup(&mut state, 2, 77, output.as_mut_ptr()), 0);
            STORE_CACHE_SEARCH = missing_cache;
            STORE_PROVIDER_QUERY = missing_provider;
        }
    }
}
