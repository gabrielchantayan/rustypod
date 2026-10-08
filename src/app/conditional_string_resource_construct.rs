//! Conditional string resource construction — FUN_081242f4 @ 0x081242f4.
//!
//! True extent [0x081242f4,0x08124334): 64 bytes, 60 A32 code bytes
//! and the fallback-object literal at +0x3c; next function starts with PUSH.
//! Raw aligned-word scan verifies two inbound plain BLs (0x08123ec8,
//! 0x08124190), no predicated inbound BLs. Body has two plain BLs,
//! no predicated BLs, one conditional and one unconditional tail B.
//! A zero flag ignores the resource ID and copy-constructs from the object
//! at 0x089ca8a0. Any nonzero flag resolves the ID through the current task's
//! provider chain and constructs from the returned C string, including NULL.
//!
//! Deliberate deviations: reuse the existing Rust context, resource lookup,
//! copy constructor and embedded constructor ports. Host tests replace the
//! fixed fallback address with valid native-width StringObject storage.
//! Static-image contents at 0x089ca8a0 are font-name text, not evidence of
//! an empty-string singleton; target code preserves the literal address.

use crate::app::resource_chain::{resource_chain_find_string, ResourceProvider};
use crate::app::string_owner_init::string_owner_embedded_init;
use crate::cxx::string_object::{string_object_copy_construct, StringObject};
use crate::util::context_field::task_ctx_field_0x30;

#[cfg(test)]
static mut TEST_FALLBACK: *const StringObject = core::ptr::null();

/// # Safety
/// `this` must be writable StringObject storage. For a zero flag the fixed
/// fallback object must be valid (self-copy preserves its payload); otherwise
/// the current task context and provider chain must be valid. Resolved text
/// must be a readable NUL-terminated string or NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn conditional_string_resource_construct(
    this: *mut StringObject, resource_id: u32, resolve_resource: u32,
) -> *mut StringObject {
    if resolve_resource == 0 {
        #[cfg(test)]
        let fallback = core::ptr::addr_of!(TEST_FALLBACK).read();
        #[cfg(not(test))]
        let fallback = 0x089ca8a0usize as *const StringObject;
        return string_object_copy_construct(this, fallback);
    }
    let head = task_ctx_field_0x30() as usize as *mut ResourceProvider;
    let text = resource_chain_find_string(head, resource_id);
    string_owner_embedded_init(this, text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use crate::app::resource_chain::{ResourceKind, ResourceProviderVTable};
    use crate::cxx::string_object::{StringObjectAssignCstrOps, STRING_OBJECT_ASSIGN_CSTR_OPS, STRING_OBJECT_VTABLE};
    use crate::util::context_field::CURRENT_TASK_CTX_BLOCK;

    static mut CONTEXT: [u32; 13] = [0; 13];
    static mut OUTPUT: [u8; 32] = [0; 32];
    static mut FAIL: bool = false;
    unsafe extern "C" fn context() -> *mut u8 { ptr::addr_of_mut!(CONTEXT).cast() }
    unsafe extern "C" fn invalid_context() -> *mut u8 { panic!("zero flag accessed context") }
    unsafe extern "C" fn allocate(this: *mut StringObject, size: usize, flags: u32) -> *mut u8 {
        assert!(size <= 32);
        assert_eq!(flags, 0);
        assert!((*this).payload.is_null());
        if FAIL { return ptr::null_mut(); }
        let output = ptr::addr_of_mut!(OUTPUT).cast::<u8>();
        (*this).payload = output;
        output
    }
    unsafe extern "C" fn clear(this: *mut StringObject) { (*this).payload = ptr::null_mut(); }
    unsafe extern "C" fn find(
        _: *mut ResourceProvider, kind: ResourceKind, id: u32, out: *mut *mut u8,
    ) -> u32 {
        assert_eq!(kind, ResourceKind::STRING);
        let text: &[u8] = match id { u32::MAX => b"resource\0", 0 => b"\0", _ => return 0 };
        *out = text.as_ptr() as *mut u8;
        1
    }
    unsafe extern "C" fn read(_: *mut ResourceProvider, _: ResourceKind, _: u32) -> u32 { 0 }
    unsafe extern "C" fn allowed(_: *mut ResourceProvider, _: *mut ResourceProvider) -> u32 { 0 }
    unsafe extern "C" fn write(_: *mut ResourceProvider, _: ResourceKind, _: u32, _: u32, _: u32) -> u32 { 0 }
    static VTABLE: ResourceProviderVTable = ResourceProviderVTable {
        slots_below: [None; 22], read, slot_5c: None, replacement_allowed: allowed, find, write,
    };
    struct Restore(unsafe extern "C" fn() -> *mut u8, StringObjectAssignCstrOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            ptr::addr_of_mut!(CURRENT_TASK_CTX_BLOCK).write_volatile(self.0);
            ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(self.1);
            TEST_FALLBACK = ptr::null();
            FAIL = false;
        } }
    }

    #[test]
    fn zero_flag_copies_fallback_and_preserves_self_copy() {
        let _context = crate::testing::TASK_CTX_BLOCK_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _assignment = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe {
            let _restore = Restore(ptr::addr_of!(CURRENT_TASK_CTX_BLOCK).read_volatile(),
                ptr::addr_of!(STRING_OBJECT_ASSIGN_CSTR_OPS).read_volatile());
            CURRENT_TASK_CTX_BLOCK = invalid_context;
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps { allocate_payload: allocate, clear_payload: clear };
            let mut fallback = StringObject { vtable: ptr::null(), payload: b"fallback\0".as_ptr() as *mut u8 };
            TEST_FALLBACK = &fallback;
            let mut out = StringObject { vtable: ptr::null(), payload: 1usize as *mut u8 };
            assert_eq!(conditional_string_resource_construct(&mut out, u32::MAX, 0), &mut out as *mut _);
            assert_eq!(core::slice::from_raw_parts(out.payload, 9), b"fallback\0");
            assert_ne!(out.payload, fallback.payload);
            let original = fallback.payload;
            assert_eq!(conditional_string_resource_construct(&mut fallback, 0, 0), &mut fallback as *mut _);
            assert_eq!(fallback.payload, original);
            assert_eq!(fallback.vtable, &STRING_OBJECT_VTABLE as *const _);
            fallback.payload = ptr::null_mut();
            conditional_string_resource_construct(&mut out, 123, 0);
            assert!(out.payload.is_null());
        }
    }

    #[test]
    fn nonzero_flags_resolve_unsigned_ids_missing_empty_and_allocation_failure() {
        let _context = crate::testing::TASK_CTX_BLOCK_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _assignment = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::CONDITIONAL_STRING_RESOURCE_CONSTRUCT, 4096,
        ) else { return; };
        unsafe {
            let _restore = Restore(ptr::addr_of!(CURRENT_TASK_CTX_BLOCK).read_volatile(),
                ptr::addr_of!(STRING_OBJECT_ASSIGN_CSTR_OPS).read_volatile());
            CURRENT_TASK_CTX_BLOCK = context;
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps { allocate_payload: allocate, clear_payload: clear };
            let provider = slab.cast::<ResourceProvider>();
            provider.write(ResourceProvider { vtable: &VTABLE, state_below_next: [ptr::null_mut(); 4], next: ptr::null_mut() });
            CONTEXT[12] = provider as usize as u32;
            TEST_FALLBACK = ptr::null();
            for flag in [1, 2, 0x8000_0000, u32::MAX] {
                let mut out = StringObject { vtable: ptr::null(), payload: 1usize as *mut u8 };
                assert_eq!(conditional_string_resource_construct(&mut out, u32::MAX, flag), &mut out as *mut _);
                assert_eq!(out.vtable, &STRING_OBJECT_VTABLE as *const _);
                assert_eq!(core::slice::from_raw_parts(out.payload, 9), b"resource\0");
                for id in [0, 1] {
                    conditional_string_resource_construct(&mut out, id, flag);
                    assert!(out.payload.is_null());
                }
                FAIL = true;
                conditional_string_resource_construct(&mut out, u32::MAX, flag);
                assert!(out.payload.is_null());
                FAIL = false;
            }
            CONTEXT[12] = 0;
            let mut out = core::mem::MaybeUninit::<StringObject>::uninit();
            conditional_string_resource_construct(out.as_mut_ptr(), u32::MAX, 1);
            assert!(out.assume_init().payload.is_null());
        }
    }
}
