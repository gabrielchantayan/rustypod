//! Tagged string resolution — `FUN_08299da8` @ `0x08299da8`.
//!
//! True extent: 44 bytes, ending at the next function's push @ 0x08299dd4.
//! Binary-scanned inbound calls: 2 plain BL (0x08299d98, 0x08299de0),
//! 0 predicated BL. Body: 1 plain BL to task_ctx_field_0x30, 0 predicated
//! BL, and two tail branches (BEQ string_object_c_str, B resource_chain_find_string).
//! Tag byte 1 selects the StringObject embedded at +4; all other tags resolve
//! the resource ID at +0x48 through the current task's provider chain.
//! Missing resources return NULL; a NULL inline payload returns the shared
//! empty string. No record or task-context NULL guard exists in stock code.
//!
//! Deliberate deviations: the repr(C) model widens embedded StringObject
//! pointers on hosts, preserving target offsets without host byte-offset
//! assumptions. The existing string_object_c_str models the firmware's shared
//! empty-string address with a static NUL byte. All callees are reused directly.

use crate::app::resource_chain::{resource_chain_find_string, ResourceProvider};
use crate::cxx::string_object::{string_object_c_str, StringObject};
use crate::util::context_field::task_ctx_field_0x30;

/// Accessed layout only; opaque bytes do not imply a recovered class identity.
#[repr(C)]
pub struct TaggedStringRecord {
    pub tag: u8,
    pub reserved: [u8; 3],
    pub inline_string: StringObject,
    pub opaque: [u32; 15],
    pub resource_id: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [(); 4] = [(); core::mem::offset_of!(TaggedStringRecord, inline_string)];
#[cfg(target_pointer_width = "32")]
const _: [(); 0x48] = [(); core::mem::offset_of!(TaggedStringRecord, resource_id)];

/// Resolves inline text or a task-local string resource.
///
/// # Safety
/// `record` must be aligned and readable through the fields selected by its
/// tag. On the resource path the current task context must exist and its
/// provider chain and vtables must be valid. Returned text remains owned by
/// the embedded string or provider, not by the caller.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tagged_string_resolve(record: *const TaggedStringRecord) -> *const u8 {
    if (*record).tag == 1 {
        string_object_c_str(core::ptr::addr_of!((*record).inline_string))
    } else {
        let head = task_ctx_field_0x30() as usize as *mut ResourceProvider;
        resource_chain_find_string(head, (*record).resource_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::resource_chain::{ResourceKind, ResourceProviderVTable};
    use crate::util::context_field::CURRENT_TASK_CTX_BLOCK;
    use core::ptr;

    fn record(tag: u8, text: *const u8, id: u32) -> TaggedStringRecord {
        TaggedStringRecord {
            tag, reserved: [0xa5; 3],
            inline_string: StringObject { vtable: ptr::null(), payload: text as *mut u8 },
            opaque: [0xdeadbeef; 15], resource_id: id,
        }
    }

    #[test]
    fn inline_text_and_null_payload_do_not_need_a_task() {
        let text = b"inline\0";
        let value = record(1, text.as_ptr(), u32::MAX);
        unsafe {
            assert_eq!(tagged_string_resolve(&value), text.as_ptr());
            let empty = record(1, ptr::null(), 0);
            assert_eq!(*tagged_string_resolve(&empty), 0);
        }
    }

    static TEXT: &[u8] = b"resource\0";
    static mut CONTEXT: [u32; 13] = [0; 13];
    unsafe extern "C" fn context() -> *mut u8 {
        ptr::addr_of_mut!(CONTEXT).cast()
    }
    unsafe extern "C" fn find(
        _provider: *mut ResourceProvider, kind: ResourceKind, id: u32, out: *mut *mut u8,
    ) -> u32 {
        if kind == ResourceKind::STRING && id == 0xfedc_ba98 {
            *out = TEXT.as_ptr() as *mut u8;
            1
        } else { 0 }
    }
    unsafe extern "C" fn read(_: *mut ResourceProvider, _: ResourceKind, _: u32) -> u32 { 0 }
    unsafe extern "C" fn allowed(_: *mut ResourceProvider, _: *mut ResourceProvider) -> u32 { 0 }
    unsafe extern "C" fn write(_: *mut ResourceProvider, _: ResourceKind, _: u32, _: u32, _: u32) -> u32 { 0 }
    static VTABLE: ResourceProviderVTable = ResourceProviderVTable {
        slots_below: [None; 22], read, slot_5c: None, replacement_allowed: allowed, find, write,
    };

    struct Restore(unsafe extern "C" fn() -> *mut u8);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { ptr::addr_of_mut!(CURRENT_TASK_CTX_BLOCK).write_volatile(self.0); } }
    }

    #[test]
    fn all_non_inline_tags_resolve_resources_and_preserve_missing_null() {
        let _lock = crate::testing::TASK_CTX_BLOCK_TEST_LOCK.lock().unwrap();
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::TAGGED_STRING_RESOLVE, 4096,
        ) else { return; };
        unsafe {
            let _restore = Restore(ptr::addr_of!(CURRENT_TASK_CTX_BLOCK).read_volatile());
            ptr::addr_of_mut!(CURRENT_TASK_CTX_BLOCK).write_volatile(context);
            let provider = slab.cast::<ResourceProvider>();
            provider.write(ResourceProvider {
                vtable: &VTABLE, state_below_next: [ptr::null_mut(); 4], next: ptr::null_mut(),
            });
            CONTEXT[12] = provider as usize as u32;
            for tag in [0, 2, 0xff] {
                let hit = record(tag, b"ignored\0".as_ptr(), 0xfedc_ba98);
                assert_eq!(tagged_string_resolve(&hit), TEXT.as_ptr());
                let miss = record(tag, b"ignored\0".as_ptr(), 0);
                assert!(tagged_string_resolve(&miss).is_null());
            }
            CONTEXT[12] = 0;
            assert!(tagged_string_resolve(&record(2, ptr::null(), 0xfedc_ba98)).is_null());
        }
    }
}
