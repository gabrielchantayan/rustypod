//! Selector string resource assignment — `FUN_0815dd44` @ 0x0815dd44.
//!
//! True extent: 96 bytes (84 code + 12 literals), next function @ 0x0815dda8.
//! Raw-image scan: one inbound plain BL @ 0x0815d4a4 and one BLEQ @
//! 0x0815df94. Body: four plain BL instructions, zero predicated BLs;
//! final B targets string_object_assign_payload @ 0x08276474.
//! Read selector byte +0x7c. Values 1, 2, 3 resolve string resources
//! 0x56a5, 0x56a6, 0x56a7 through the current task and assign the result
//! to the destination. Other values leave it untouched without context access.
//! Missing/empty resources clear through the existing assignment helper.
//!
//! Deliberate deviations: ordinary Rust calls replace the shared branch and
//! tail branch. The existing StringObject virtual allocation/clear boundary
//! remains in use; it must be wired before hooking. No new seams or guessed
//! class/resource identities. The selector offset remains a byte offset on hosts.

use crate::app::resource_chain::{resource_chain_find_string, ResourceProvider};
use crate::cxx::string_object::{string_object_assign_payload, StringObject};
use crate::util::context_field::task_ctx_field_0x30;

/// # Safety
/// `receiver` must be readable through +0x7c. For selectors 1..=3, the current
/// task context, provider chain and destination assignment operations must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selector_string_resource_assign(
    receiver: *const u8, destination: *mut StringObject,
) {
    let selector = receiver.add(0x7c).read();
    let resource_id = match selector {
        1 => 0x56a5,
        2 => 0x56a6,
        3 => 0x56a7,
        _ => return,
    };
    let head = task_ctx_field_0x30() as usize as *mut ResourceProvider;
    let text = resource_chain_find_string(head, resource_id);
    string_object_assign_payload(destination, text);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use crate::app::resource_chain::{ResourceKind, ResourceProviderVTable};
    use crate::cxx::string_object::{StringObjectAssignCstrOps, STRING_OBJECT_ASSIGN_CSTR_OPS};
    use crate::util::context_field::CURRENT_TASK_CTX_BLOCK;

    static mut CONTEXT: [u32; 13] = [0; 13];
    static mut FAIL_ALLOCATION: bool = false;
    unsafe extern "C" fn context() -> *mut u8 { ptr::addr_of_mut!(CONTEXT).cast() }
    unsafe extern "C" fn invalid_context() -> *mut u8 { panic!("invalid selector accessed context") }
    unsafe extern "C" fn find(
        _: *mut ResourceProvider, kind: ResourceKind, id: u32, out: *mut *mut u8,
    ) -> u32 {
        assert_eq!(kind, ResourceKind::STRING);
        let text: &[u8] = match id { 0x56a5 => b"first\0", 0x56a6 => b"second\0", 0x56a7 => b"\0", _ => panic!("wrong resource id") };
        *out = text.as_ptr() as *mut u8;
        1
    }
    unsafe extern "C" fn read(_: *mut ResourceProvider, _: ResourceKind, _: u32) -> u32 { 0 }
    unsafe extern "C" fn allowed(_: *mut ResourceProvider, _: *mut ResourceProvider) -> u32 { 0 }
    unsafe extern "C" fn write(_: *mut ResourceProvider, _: ResourceKind, _: u32, _: u32, _: u32) -> u32 { 0 }
    static VTABLE: ResourceProviderVTable = ResourceProviderVTable {
        slots_below: [None; 22], read, slot_5c: None, replacement_allowed: allowed, find, write,
    };
    unsafe extern "C" fn allocate(this: *mut StringObject, size: usize, flags: u32) -> *mut u8 {
        assert!(size == 6 || size == 7);
        assert_eq!(flags, 0);
        if FAIL_ALLOCATION { ptr::null_mut() } else { (*this).payload }
    }
    unsafe extern "C" fn clear(this: *mut StringObject) { (*this).payload.write(0); }
    struct Restore(unsafe extern "C" fn() -> *mut u8, StringObjectAssignCstrOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            ptr::addr_of_mut!(CURRENT_TASK_CTX_BLOCK).write_volatile(self.0);
            ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(self.1);
            FAIL_ALLOCATION = false;
        } }
    }
    #[test]
    fn selector_bounds_assignment_missing_empty_and_allocation_failure() {
        let _context_lock = crate::testing::TASK_CTX_BLOCK_TEST_LOCK.lock().unwrap();
        let _assignment_lock = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock().unwrap();
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::SELECTOR_STRING_RESOURCE_ASSIGN, 4096,
        ) else { return; };
        let mut receiver = [0xa5u8; 0x7d];
        let mut storage = [0xccu8; 16];
        let mut destination = StringObject { vtable: ptr::null(), payload: storage.as_mut_ptr() };
        unsafe {
            let _restore = Restore(
                ptr::addr_of!(CURRENT_TASK_CTX_BLOCK).read_volatile(),
                ptr::addr_of!(STRING_OBJECT_ASSIGN_CSTR_OPS).read_volatile(),
            );
            ptr::addr_of_mut!(CURRENT_TASK_CTX_BLOCK).write_volatile(invalid_context);
            for selector in 0..=255u8 {
                if (1..=3).contains(&selector) { continue; }
                receiver[0x7c] = selector;
                selector_string_resource_assign(receiver.as_ptr(), &mut destination);
                assert_eq!(storage, [0xcc; 16]);
            }
            ptr::addr_of_mut!(CURRENT_TASK_CTX_BLOCK).write_volatile(context);
            ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(StringObjectAssignCstrOps {
                allocate_payload: allocate, clear_payload: clear,
            });
            let provider = slab.cast::<ResourceProvider>();
            provider.write(ResourceProvider { vtable: &VTABLE, state_below_next: [ptr::null_mut(); 4], next: ptr::null_mut() });
            CONTEXT[12] = provider as usize as u32;
            for (selector, expected) in [(1, &b"first\0"[..]), (2, &b"second\0"[..]), (3, &b"\0"[..])] {
                storage.fill(0xcc);
                receiver[0x7c] = selector;
                selector_string_resource_assign(receiver.as_ptr(), &mut destination);
                assert_eq!(&storage[..expected.len()], expected);
                assert!(storage[expected.len()..].iter().all(|&b| b == 0xcc));
            }
            receiver[0x7c] = 1;
            storage.fill(0xcc);
            FAIL_ALLOCATION = true;
            selector_string_resource_assign(receiver.as_ptr(), &mut destination);
            assert_eq!(storage, [0xcc; 16]);
            CONTEXT[12] = 0;
            selector_string_resource_assign(receiver.as_ptr(), &mut destination);
            assert_eq!(storage[0], 0);
            assert_eq!(&storage[1..], &[0xcc; 15]);
            assert!(receiver[..0x7c].iter().all(|&b| b == 0xa5));
        }
    }
}
