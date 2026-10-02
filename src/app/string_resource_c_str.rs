//! String resource accessor — `FUN_0829134c` @ `0x0829134c`.
//!
//! Raw extent: 68 instruction bytes plus the four-byte `"Str "` literal at
//! 0x08291390; next real function starts at 0x08291394 (72 bytes total).
//! Whole-image decoding finds two plain inbound BL calls (0x08290de4,
//! 0x08291828), zero predicated BL calls. Body: one plain BL to 0x082915d4,
//! one indirect BLX through slot +0x120, and two tail branches.
//!
//! Query slot +0x120. Zero selects resource_chain_find(head at +0x38,
//! STRING, id at +0x44), preserving NULL on a miss. Any nonzero result
//! calls the unported cache preparation at 0x082915d4, then returns the
//! embedded StringObject at +0x10c through the existing c_str port.
//! Raw cache-preparation code checks byte +0x1f1, resolves the same resource,
//! assigns it through 0x08276474, and sets that byte; no callee identity is
//! inferred beyond this observed role.
//!
//! Deviations: tail branches are Rust calls; pointer-bearing words widen on
//! hosts through repr(C) fields, and only the unported cache preparation has
//! a replaceable host seam. The existing c_str port models the shared empty
//! C string with a static NUL rather than its retail address.

use crate::app::resource_chain::{resource_chain_find, ResourceKind, ResourceProvider};
use crate::cxx::string_object::{string_object_c_str, StringObject};

pub type CachedStringQuery = unsafe extern "C" fn(*mut StringResourceObject) -> u32;
pub type PrepareStringCache = unsafe extern "C" fn(*mut StringResourceObject);

#[repr(C)]
pub struct StringResourceVtable {
    pub unresolved_000_11c: [usize; 72],
    pub uses_cached_string: CachedStringQuery,
}

/// Decoded fields; all intervening target words are deliberately opaque.
#[repr(C)]
pub struct StringResourceObject {
    pub vtable: *const StringResourceVtable,
    pub unresolved_004_034: [usize; 13],
    pub resources: *mut ResourceProvider,
    pub unresolved_03c_040: [usize; 2],
    pub resource_id: usize,
    pub unresolved_048_108: [usize; 49],
    pub cached_string: StringObject,
}

#[cfg(target_os = "none")]
unsafe fn prepare_cache(object: *mut StringResourceObject) {
    let prepare: PrepareStringCache = unsafe { core::mem::transmute(0x0829_15d4usize) };
    unsafe { prepare(object) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepare_cache(_: *mut StringResourceObject) {
    panic!("install STRING_RESOURCE_PREPARE_CACHE for host cached-string calls");
}

#[cfg(not(target_os = "none"))]
pub static mut STRING_RESOURCE_PREPARE_CACHE: PrepareStringCache = missing_prepare_cache;

#[cfg(not(target_os = "none"))]
unsafe fn prepare_cache(object: *mut StringResourceObject) {
    let prepare = unsafe { core::ptr::addr_of!(STRING_RESOURCE_PREPARE_CACHE).read_volatile() };
    unsafe { prepare(object) };
}

/// # Safety
/// Object, virtual query, provider chain, and selected cache preparation must
/// satisfy the unchecked retail contracts. The query may mutate the object.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_resource_c_str(object: *mut StringResourceObject) -> *const u8 {
    let vtable = unsafe { (*object).vtable };
    if unsafe { ((*vtable).uses_cached_string)(object) } == 0 {
        return unsafe { resource_chain_find((*object).resources, ResourceKind::STRING, (*object).resource_id as u32) }.cast_const();
    }
    unsafe { prepare_cache(object) };
    unsafe { string_object_c_str(core::ptr::addr_of!((*object).cached_string)) }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::resource_chain::ResourceProviderVTable;
    use core::ptr;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    unsafe extern "C" fn query(object: *mut StringResourceObject) -> u32 {
        // Verify that lookup reloads the ID after the virtual call.
        unsafe { (*object).resource_id = 37; (*object).unresolved_004_034[0] as u32 }
    }
    unsafe extern "C" fn prepare(object: *mut StringResourceObject) {
        unsafe {
            (*object).cached_string.payload = (*object).unresolved_004_034[1] as *mut u8;
            (*object).unresolved_004_034[2] += 1;
        }
    }
    unsafe extern "C" fn find(provider: *mut ResourceProvider, kind: ResourceKind, id: u32, out: *mut *mut u8) -> u32 {
        assert_eq!(kind, ResourceKind::STRING);
        assert_eq!(id, 37);
        unsafe { *out = (*provider).state_below_next[0]; }
        0x8000_0000
    }
    unsafe extern "C" fn read(_: *mut ResourceProvider, _: ResourceKind, _: u32) -> u32 { 0 }
    unsafe extern "C" fn replace(_: *mut ResourceProvider, _: *mut ResourceProvider) -> u32 { 0 }
    unsafe extern "C" fn write(_: *mut ResourceProvider, _: ResourceKind, _: u32, _: u32, _: u32) -> u32 { 0 }

    #[test]
    fn direct_miss_and_hit_preserve_resource_result() {
        let vtable = StringResourceVtable { unresolved_000_11c: [0; 72], uses_cached_string: query };
        let mut object = fixture(&vtable);
        unsafe { assert!(string_resource_c_str(&mut object).is_null()); }
        let provider_vtable = ResourceProviderVTable {
            slots_below: [None; 22], read, slot_5c: None, replacement_allowed: replace, find, write,
        };
        let mut text = *b"resource\0";
        let mut provider = ResourceProvider { vtable: &provider_vtable, state_below_next: [ptr::null_mut(); 4], next: ptr::null_mut() };
        provider.state_below_next[0] = text.as_mut_ptr();
        object.resources = &mut provider;
        unsafe { assert_eq!(string_resource_c_str(&mut object), text.as_ptr()); }
        assert_eq!(object.unresolved_004_034[2], 0);
    }

    #[test]
    fn nonzero_query_prepares_before_access_and_empty_cache_is_nonnull() {
        let _guard = LOCK.lock();
        let old = unsafe { STRING_RESOURCE_PREPARE_CACHE };
        unsafe { STRING_RESOURCE_PREPARE_CACHE = prepare; }
        let vtable = StringResourceVtable { unresolved_000_11c: [0; 72], uses_cached_string: query };
        let mut object = fixture(&vtable);
        object.unresolved_004_034[0] = 0x8000_0000;
        let text = *b"cached\0";
        object.unresolved_004_034[1] = text.as_ptr() as usize;
        unsafe { assert_eq!(string_resource_c_str(&mut object), text.as_ptr()); }
        assert_eq!(object.unresolved_004_034[2], 1);
        object.unresolved_004_034[1] = 0;
        let empty = unsafe { string_resource_c_str(&mut object) };
        assert!(!empty.is_null());
        unsafe { assert_eq!(*empty, 0); STRING_RESOURCE_PREPARE_CACHE = old; }
        assert_eq!(object.unresolved_004_034[2], 2);
    }

    fn fixture(vtable: *const StringResourceVtable) -> StringResourceObject {
        StringResourceObject {
            vtable, unresolved_004_034: [0; 13], resources: ptr::null_mut(),
            unresolved_03c_040: [0; 2], resource_id: 0,
            unresolved_048_108: [0; 49],
            cached_string: StringObject { vtable: ptr::null(), payload: ptr::null_mut() },
        }
    }
}
