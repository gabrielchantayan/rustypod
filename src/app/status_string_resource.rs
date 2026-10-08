//! `status_string_resource` — `FUN_08114e08` @ 0x08114e08.
//! True extent: 60 bytes (48 code + 12 literal bytes); next function starts
//! at 0x08114e44. Raw A32 decoding finds two incoming plain BLs at
//! 0x081127c8 and 0x08112880, no predicated incoming BLs; the body has two
//! plain BLs, no predicated BLs, and a tail B to 0x0827239c.
//!
//! Normalize retail status, select string ID 0x0dad0ae3 for status 1,
//! 0x0dad0ae2 for status 3, or 0x6411 otherwise, and look it up through
//! the current task's provider chain. Callers append the non-NULL result
//! to text; the incoming receiver is unused.
//!
//! Deliberate deviations: reuse the existing Rust callees and their host
//! seams; LLVM may inline the context accessor instead of retaining its BL.

use super::resource_chain::{resource_chain_find_string, ResourceProvider};
use super::status_code_normalize::status_code_normalize;
use crate::util::context_field::task_ctx_field_0x30;

/// # Safety
/// Requires a valid current task context and a valid resource provider chain.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn status_string_resource() -> *const u8 {
    let id = match status_code_normalize() {
        1 => 0x0dad_0ae3,
        3 => 0x0dad_0ae2,
        _ => 0x6411,
    };
    let head = task_ctx_field_0x30() as usize as *mut ResourceProvider;
    resource_chain_find_string(head, id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::object_byte_0x450_initialize::{
        OBJECT_BYTE_0X450_INITIALIZER, RETAIL_BYTE_INITIALIZER_TEST_LOCK,
    };
    use super::super::resource_chain::{ResourceKind, ResourceProviderVTable};
    use crate::util::context_field::CURRENT_TASK_CTX_BLOCK;
    use core::ptr::{addr_of_mut, null_mut};

    static mut RAW_STATUS: u8 = 0;
    static mut CONTEXT: *mut u8 = null_mut();
    static DEFAULT_TEXT: &[u8] = b"default\0";
    static FIRST_TEXT: &[u8] = b"first\0";
    static THIRD_TEXT: &[u8] = b"third\0";

    unsafe extern "C" fn query(_: u32) -> u8 { RAW_STATUS }
    unsafe extern "C" fn context() -> *mut u8 { CONTEXT }
    unsafe extern "C" fn find(provider: *mut ResourceProvider, kind: ResourceKind,
        id: u32, found: *mut *mut u8) -> u32 {
        if kind != ResourceKind::STRING || (*provider).state_below_next[0].is_null() {
            return 0;
        }
        let text = match id {
            0x6411 => DEFAULT_TEXT,
            0x0dad_0ae3 => FIRST_TEXT,
            0x0dad_0ae2 => THIRD_TEXT,
            _ => return 0,
        };
        found.write(text.as_ptr() as *mut u8);
        1
    }
    unsafe extern "C" fn read(_: *mut ResourceProvider, _: ResourceKind, _: u32) -> u32 { 0 }
    unsafe extern "C" fn replacement(_: *mut ResourceProvider, _: *mut ResourceProvider) -> u32 { 0 }
    unsafe extern "C" fn write(_: *mut ResourceProvider, _: ResourceKind, _: u32, _: u32, _: u32) -> u32 { 0 }

    #[test]
    fn selects_status_text_and_preserves_missing_chain_results() {
        let _status_lock = RETAIL_BYTE_INITIALIZER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _ctx_lock = crate::testing::TASK_CTX_BLOCK_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::STATUS_STRING_RESOURCE, 4096) else { return };
        unsafe {
            let old_query = OBJECT_BYTE_0X450_INITIALIZER;
            let old_context = CURRENT_TASK_CTX_BLOCK;
            struct Restore(super::super::object_byte_0x450_initialize::RetailByteInitializer,
                unsafe extern "C" fn() -> *mut u8);
            impl Drop for Restore {
                fn drop(&mut self) { unsafe {
                    addr_of_mut!(OBJECT_BYTE_0X450_INITIALIZER).write(self.0);
                    addr_of_mut!(CURRENT_TASK_CTX_BLOCK).write(self.1);
                } }
            }
            let _restore = Restore(old_query, old_context);
            let vtable = ResourceProviderVTable {
                slots_below: [None; 22], read, slot_5c: None,
                replacement_allowed: replacement, find, write,
            };
            let head = slab.add(0x100).cast::<ResourceProvider>();
            let tail = slab.add(0x200).cast::<ResourceProvider>();
            head.write(ResourceProvider { vtable: &vtable,
                state_below_next: [null_mut(); 4], next: tail });
            tail.write(ResourceProvider { vtable: &vtable,
                state_below_next: [slab; 4], next: null_mut() });
            CONTEXT = slab;
            slab.add(0x30).cast::<u32>().write(head as usize as u32);
            addr_of_mut!(OBJECT_BYTE_0X450_INITIALIZER).write(query);
            addr_of_mut!(CURRENT_TASK_CTX_BLOCK).write(context);
            for (raw, text) in [(0, DEFAULT_TEXT), (1, FIRST_TEXT), (2, THIRD_TEXT),
                (3, DEFAULT_TEXT), (0x80, DEFAULT_TEXT), (255, DEFAULT_TEXT)] {
                RAW_STATUS = raw;
                assert_eq!(status_string_resource(), text.as_ptr());
            }
            (*tail).state_below_next = [null_mut(); 4];
            assert!(status_string_resource().is_null());
            slab.add(0x30).cast::<u32>().write(0);
            assert!(status_string_resource().is_null());
        }
    }
}
