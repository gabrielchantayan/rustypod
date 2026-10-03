//! Image lookup cache — original `FUN_08223c88` @ 0x08223c88.
//! True extent: 200 bytes through 0x08223d50 exclusive (196 code + four-byte
//! StringObject vtable literal). Raw decoding: three plain BLs, one BLNE,
//! one indirect BLX; two inbound plain BLs and no predicated inbound BLs.
//! Reuses a cached (key, kind) lookup; otherwise dereferences the provider
//! handle and invokes its slot +0x20 with the kind's image format and output
//! pointers. Success caches the inputs; failure clears key/string/index/count
//! but deliberately leaves cached kind unchanged. The fourth input is copied
//! to a mutable stack word passed to the provider, not to caller storage.
//! Deviations: repr(C) pointer fields widen on hosts. NULL assignment is
//! expanded to its actual virtual clear (+0xc), avoiding the existing helper's
//! unwired default seam. The empty temporary's destruction has no payload;
//! retain the existing destructor. Its stack-address self-assignment guard is
//! impossible for a valid, disjoint caller object and is omitted.

use crate::cxx::handle::handle_deref_or_null;
use crate::cxx::string_object::{string_object_destroy, StringObject, STRING_OBJECT_VTABLE};
use super::image_format::image_format_for_kind_kind4_override;

#[repr(C)]
pub struct ImageLookupCache {
    pub opaque: [u32; 13],
    pub provider: *const *mut u8,
    pub key: u32,
    pub kind: u32,
    pub path: StringObject,
    pub index: u32,
    pub count: u32,
}

type Lookup = unsafe extern "C" fn(*mut u8, u32, u32, *mut StringObject,
    *mut u32, *mut u32, *mut u32) -> u32;

/// Refresh the cached image lookup, returning 1 on success/cache hit, 0 on failure.
/// The provider and both virtual interfaces must be valid; no NULL provider guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn image_lookup_cache_refresh(
    cache: *mut ImageLookupCache, key: u32, kind: u32, mut context: u32,
) -> u32 {
    if (*cache).key == key && (*cache).kind == kind { return 1; }
    let provider = handle_deref_or_null(core::ptr::addr_of!((*cache).provider));
    let format = image_format_for_kind_kind4_override(kind);
    let vtable = provider.cast::<*const usize>().read();
    let lookup: Lookup = core::mem::transmute(vtable.add(8).read());
    if lookup(provider, key, format, core::ptr::addr_of_mut!((*cache).path),
        core::ptr::addr_of_mut!((*cache).index), core::ptr::addr_of_mut!((*cache).count),
        &mut context) != 0 {
        (*cache).key = key;
        (*cache).kind = kind;
        return 1;
    }
    (*cache).key = 0;
    let mut empty = StringObject { vtable: &STRING_OBJECT_VTABLE, payload: core::ptr::null_mut() };
    let path = core::ptr::addr_of_mut!((*cache).path);
    let clear: unsafe extern "C" fn(*mut StringObject) =
        core::mem::transmute((*(*path).vtable).slots[3]);
    clear(path);
    string_object_destroy(&mut empty);
    (*cache).index = u32::MAX;
    (*cache).count = 0;
    0
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(ImageLookupCache, provider) == 0x34);
    assert!(core::mem::offset_of!(ImageLookupCache, path) == 0x40);
    assert!(core::mem::offset_of!(ImageLookupCache, count) == 0x4c);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::StringObjectVtable;

    #[repr(C)]
    struct Provider { vtable: *const usize, calls: u32, succeed: u32 }
    unsafe extern "C" fn lookup(provider: *mut u8, key: u32, format: u32,
        path: *mut StringObject, index: *mut u32, count: *mut u32, context: *mut u32) -> u32 {
        let provider = &mut *provider.cast::<Provider>();
        provider.calls += 1;
        // Model an observable lookup result, including partial writes on failure.
        index.write(key ^ format);
        count.write(context.read());
        context.write(0);
        (*path).payload = core::ptr::without_provenance_mut(1);
        provider.succeed
    }
    unsafe extern "C" fn clear(path: *mut StringObject) { (*path).payload = core::ptr::null_mut(); }

    #[test]
    fn cache_transitions_and_failed_partial_output() {
        let mut slots = [0usize; 9]; slots[8] = lookup as *const () as usize;
        let mut provider = Provider { vtable: slots.as_ptr(), calls: 0, succeed: 7 };
        let cell = (&mut provider as *mut Provider).cast::<u8>();
        let path_vtable = StringObjectVtable { slots: [0, 0, 0, clear as *const () as usize, 0, 0] };
        let mut cache = ImageLookupCache { opaque: [0xa5a5a5a5; 13], provider: &cell,
            key: 42, kind: 4, path: StringObject { vtable: &path_vtable, payload: core::ptr::null_mut() },
            index: 99, count: 88 };
        unsafe {
            // A hit must not even dereference a missing provider.
            cache.provider = core::ptr::null();
            assert_eq!(image_lookup_cache_refresh(&mut cache, 42, 4, 3), 1);
            assert_eq!((cache.index, cache.count), (99, 88));
            cache.provider = &cell;
            assert_eq!(image_lookup_cache_refresh(&mut cache, 43, 4, 13), 1);
            assert_eq!((cache.key, cache.kind, cache.index, cache.count), (43, 4, 43 ^ 0x400, 13));
            assert_eq!(image_lookup_cache_refresh(&mut cache, 43, 4, 99), 1);
            assert_eq!(provider.calls, 1);
            // Same key, changed kind is a miss; invalid kind retains NONE format.
            assert_eq!(image_lookup_cache_refresh(&mut cache, 43, u32::MAX, 17), 1);
            assert_eq!((cache.index, cache.count), (43 ^ u32::MAX, 17));
            provider.succeed = 0;
            assert_eq!(image_lookup_cache_refresh(&mut cache, 44, 2, 19), 0);
            assert_eq!((cache.key, cache.kind, cache.index, cache.count), (0, u32::MAX, u32::MAX, 0));
            assert!(cache.path.payload.is_null());
            assert_eq!(provider.calls, 3);
            provider.succeed = 1;
            assert_eq!(image_lookup_cache_refresh(&mut cache, 44, 2, 23), 1);
            assert_eq!((cache.key, cache.kind, cache.count), (44, 2, 23));
            assert_eq!(cache.opaque, [0xa5a5a5a5; 13]);
        }
    }
}
