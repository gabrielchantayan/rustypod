//! Localized "All" label — FUN_081a9c28 @ 0x081a9c28.
//! True extent: 96 bytes (92 code, four-byte "All\0" literal); next entry
//! at 0x081a9c88. Raw A32 verifies two inbound plain BLs, zero predicated;
//! outbound: five plain BLs, one BLNE, and one register BLX (vtable +0x20).
//! Fetch singleton resource 1 into a temporary StringObject, copy its C string
//! to the output, destroy the temporary, then assign "All" if output is empty.
//! Deliberate deviations: repr(C) pointers widen on hosts; unused incoming
//! registers are not used to seed the temporary before the virtual constructor.
//! Existing singleton/string seams are reused, including their documented
//! unported virtual allocation/constructor boundaries; this is not hook-ready
//! until those boundaries are wired. Hosts can replace only singleton access.

use crate::app::singletons::lazy_singleton_0x80;
use crate::cxx::string_object::{
    StringObject, string_object_c_str, string_object_assign_payload,
    string_object_destroy, string_object_is_empty, string_object_assign_cstr,
};

#[repr(C)]
pub struct LabelProviderVtable {
    pub preceding: [usize; 8],
    pub construct_string: unsafe extern "C" fn(*mut StringObject, *mut LabelProvider, u32),
}

#[repr(C)]
pub struct LabelProvider {
    pub vtable: *const LabelProviderVtable,
}

#[cfg(not(target_os = "none"))]
pub static mut ALL_LABEL_PROVIDER_GET: unsafe extern "C" fn() -> *mut u8 = lazy_singleton_0x80;

/// Resolve resource 1, with an English fallback based on the resulting output.
///
/// # Safety
/// `out` must be a valid mutable StringObject; the singleton must have a valid
/// +0x20 virtual constructor that initializes both words of the temporary.
/// Its returned payload must remain valid until the temporary is destroyed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn all_label_resolve(
    _view: *mut u8, _source: *mut u8, _index: u32, out: *mut StringObject,
) {
    #[cfg(target_os = "none")]
    let provider = lazy_singleton_0x80().cast::<LabelProvider>();
    #[cfg(not(target_os = "none"))]
    let provider = (core::ptr::addr_of!(ALL_LABEL_PROVIDER_GET).read_volatile())()
        .cast::<LabelProvider>();
    let mut temporary = core::mem::MaybeUninit::<StringObject>::uninit();
    ((*(*provider).vtable).construct_string)(temporary.as_mut_ptr(), provider, 1);
    string_object_assign_payload(out, string_object_c_str(temporary.as_ptr()));
    string_object_destroy(temporary.as_mut_ptr());
    if string_object_is_empty(out) {
        string_object_assign_cstr(out, b"All\0".as_ptr());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::{
        StringObjectAssignCstrOps, StringObjectOps, STRING_OBJECT_ASSIGN_CSTR_OPS,
        STRING_OBJECT_OPS, STRING_OBJECT_VTABLE,
    };
    use core::ptr::{null_mut, addr_of_mut};

    static mut SOURCE: *mut u8 = null_mut();
    static mut FAIL: bool = false;
    static mut RELEASED: bool = false;
    static mut STORAGE: [u8; 32] = [0; 32];
    static VTABLE: LabelProviderVtable = LabelProviderVtable {
        preceding: [0; 8], construct_string: construct,
    };
    unsafe extern "C" fn get() -> *mut u8 {
        static mut PROVIDER: LabelProvider = LabelProvider { vtable: &VTABLE };
        addr_of_mut!(PROVIDER).cast()
    }
    unsafe extern "C" fn construct(out: *mut StringObject, _: *mut LabelProvider, id: u32) {
        assert_eq!(id, 1);
        out.write(StringObject { vtable: &STRING_OBJECT_VTABLE, payload: SOURCE });
    }
    unsafe extern "C" fn allocate(out: *mut StringObject, size: usize, flags: u32) -> *mut u8 {
        assert_eq!(flags, 0);
        assert!(size <= 32);
        if FAIL { return null_mut(); }
        let storage = addr_of_mut!(STORAGE).cast::<u8>();
        (*out).payload = storage;
        storage
    }
    unsafe extern "C" fn clear(out: *mut StringObject) { (*out).payload = null_mut(); }
    unsafe extern "C" fn release(out: *mut StringObject) {
        assert_eq!((*out).payload, SOURCE);
        RELEASED = true;
        (*out).payload = null_mut();
    }
    struct Restore(StringObjectAssignCstrOps, StringObjectOps, unsafe extern "C" fn() -> *mut u8);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            STRING_OBJECT_ASSIGN_CSTR_OPS = self.0;
            STRING_OBJECT_OPS = self.1;
            ALL_LABEL_PROVIDER_GET = self.2;
        } }
    }

    #[test]
    fn localized_empty_and_failed_replacement_preserve_retail_fallback_rules() {
        let _assign = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock()
            .unwrap_or_else(|e| e.into_inner());
        let _release = crate::cxx::string_object::tests::STRING_OBJECT_OPS_TEST_LOCK.lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            let _restore = Restore(STRING_OBJECT_ASSIGN_CSTR_OPS, STRING_OBJECT_OPS, ALL_LABEL_PROVIDER_GET);
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps { allocate_payload: allocate, clear_payload: clear };
            STRING_OBJECT_OPS = StringObjectOps { release_payload: release };
            ALL_LABEL_PROVIDER_GET = get;
            for source in [null_mut(), b"\0".as_ptr() as *mut u8, b"Tous\0".as_ptr() as *mut u8] {
                for fail in [false, true] {
                    for initial in [null_mut(), b"old\0".as_ptr() as *mut u8] {
                        SOURCE = source;
                        FAIL = fail;
                        RELEASED = false;
                        let mut out = StringObject { vtable: &STRING_OBJECT_VTABLE, payload: initial };
                        all_label_resolve(null_mut(), null_mut(), u32::MAX, &mut out);
                        assert!(RELEASED);
                        let source_empty = source.is_null() || source.read() == 0;
                        let expected: &[u8] = if !fail {
                            if source_empty { b"All\0" } else { b"Tous\0" }
                        } else if source_empty || initial.is_null() { b"\0" } else { b"old\0" };
                        assert_eq!(core::slice::from_raw_parts(string_object_c_str(&out), expected.len()), expected);
                        if !fail { assert_ne!(out.payload, source); }
                    }
                }
            }
        }
    }
}
