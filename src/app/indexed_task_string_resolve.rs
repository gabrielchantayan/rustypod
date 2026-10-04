//! Indexed task string resolution — `FUN_081eb090` @ 0x081eb090.
//!
//! True extent: 52 bytes (44 code + 8 literal pool), next push @ 0x081eb0c4.
//! Raw-image scan: 2 inbound plain BLs (0x081ebbb0, 0x081ed344), zero
//! predicated BLs. Body: one plain BL, zero predicated BLs, two tail branches.
//! Ignore the receiver. For unsigned indices below 23, read the first word
//! of the eight-byte record at 0x089cc500 and resolve that string resource
//! through the current task's provider chain. Otherwise return the C string
//! of the fixed StringObject at 0x089ca8a0, including its NULL-payload fallback.
//!
//! Deliberate deviations: host tests substitute valid runtime data for the
//! fixed addresses, as in string_object_differs_from_static_object. Static
//! image bytes at these addresses are unrelated text, so no resource IDs or
//! fallback identity are inferred. Runtime addresses and all three existing
//! callees are preserved; native StringObject pointers widen only on hosts.

use crate::app::resource_chain::{resource_chain_find_string, ResourceProvider};
use crate::cxx::string_object::{string_object_c_str, StringObject};
use crate::util::context_field::task_ctx_field_0x30;

#[cfg(test)]
static mut TEST_RECORDS: *const u32 = core::ptr::null();
#[cfg(test)]
static mut TEST_FALLBACK: *const StringObject = core::ptr::null();

/// # Safety
/// For indices below 23, the runtime table and current task context/provider
/// chain must be valid. Otherwise the fixed fallback object must be readable.
/// The returned text is borrowed; a missing resource returns NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_task_string_resolve(
    _receiver: *const u8, index: u32,
) -> *const u8 {
    if index >= 23 {
        #[cfg(test)]
        let fallback = core::ptr::addr_of!(TEST_FALLBACK).read();
        #[cfg(not(test))]
        let fallback = 0x089ca8a0usize as *const StringObject;
        return string_object_c_str(fallback);
    }
    let head = task_ctx_field_0x30() as usize as *mut ResourceProvider;
    #[cfg(test)]
    let records = core::ptr::addr_of!(TEST_RECORDS).read();
    #[cfg(not(test))]
    let records = 0x089cc500usize as *const u32;
    let id = records.add(index as usize * 2).read();
    resource_chain_find_string(head, id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::resource_chain::{ResourceKind, ResourceProviderVTable};
    use crate::util::context_field::CURRENT_TASK_CTX_BLOCK;
    use core::ptr;

    static TEXT: &[u8] = b"selected resource\0";
    static mut CONTEXT: [u32; 13] = [0; 13];
    unsafe extern "C" fn context() -> *mut u8 { ptr::addr_of_mut!(CONTEXT).cast() }
    unsafe extern "C" fn find(
        _: *mut ResourceProvider, kind: ResourceKind, id: u32, out: *mut *mut u8,
    ) -> u32 {
        if kind == ResourceKind::STRING && (id == 0x8000_0000 || id == 0xffff_fffe) {
            *out = TEXT.as_ptr() as *mut u8;
            7
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
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(CURRENT_TASK_CTX_BLOCK).write_volatile(self.0);
                TEST_RECORDS = ptr::null();
                TEST_FALLBACK = ptr::null();
            }
        }
    }

    #[test]
    fn unsigned_bounds_record_stride_missing_and_fallback_payload() {
        let _lock = crate::testing::TASK_CTX_BLOCK_TEST_LOCK.lock().unwrap();
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::INDEXED_TASK_STRING_RESOLVE, 4096,
        ) else { return; };
        let mut records = [0xdead_beefu32; 46];
        records[0] = 0x8000_0000;
        records[44] = 0xffff_fffe;
        let fallback_text = b"fallback\0";
        let mut fallback = StringObject { vtable: ptr::null(), payload: fallback_text.as_ptr() as *mut u8 };
        unsafe {
            let _restore = Restore(ptr::addr_of!(CURRENT_TASK_CTX_BLOCK).read_volatile());
            ptr::addr_of_mut!(CURRENT_TASK_CTX_BLOCK).write_volatile(context);
            let provider = slab.cast::<ResourceProvider>();
            provider.write(ResourceProvider {
                vtable: &VTABLE, state_below_next: [ptr::null_mut(); 4], next: ptr::null_mut(),
            });
            CONTEXT[12] = provider as usize as u32;
            TEST_RECORDS = records.as_ptr();
            TEST_FALLBACK = &fallback;
            for index in [0, 22] {
                assert_eq!(indexed_task_string_resolve(ptr::null(), index), TEXT.as_ptr());
            }
            assert!(indexed_task_string_resolve(ptr::null(), 1).is_null());
            CONTEXT[12] = 0;
            assert!(indexed_task_string_resolve(ptr::null(), 0).is_null());
            TEST_RECORDS = ptr::null();
            ptr::addr_of_mut!(CURRENT_TASK_CTX_BLOCK).write_volatile(invalid_context);
            for index in [23, 24, 0x8000_0000, u32::MAX] {
                assert_eq!(indexed_task_string_resolve(ptr::null(), index), fallback_text.as_ptr());
            }
            fallback.payload = ptr::null_mut();
            assert_eq!(*indexed_task_string_resolve(ptr::null(), 23), 0);
        }
    }
    unsafe extern "C" fn invalid_context() -> *mut u8 {
        panic!("out-of-range index must not access the task context")
    }
}
