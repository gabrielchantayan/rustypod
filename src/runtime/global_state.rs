//! Default-heap free-byte lookup.
//!
//! `default_heap_free_bytes_get` — original: `FUN_0807b180` @
//! `0x0807b180` (24 bytes, including the literal at `0x0807b198`).
//!
//! Raw ARM is:
//!
//! ```text
//! 0807b180: push {r4, lr}
//! 0807b184: bl   0x08077250
//! 0807b188: ldr  r0, [pc, #8]   ; 0x0807b198 = 0x089ca638
//! 0807b18c: ldr  r0, [r0]
//! 0807b190: ldr  r0, [r0]
//! 0807b194: pop  {r4, pc}
//! ```
//!
//! The call is the ported `lazy_init_default_heap` guard: it creates the
//! 32 KiB default heap only while the `DEFAULT_HEAP` handle is null. The two
//! following unchecked loads read that handle at `0x089ca638`, then word zero
//! of the `HeapDescriptor` it identifies. The established heap layout names
//! that word `free_bytes`. This getter intentionally adds no null check,
//! ownership rule, or caching: initialization precedes both raw loads on every
//! call, exactly as in the firmware.

use crate::heap::types::DEFAULT_HEAP;
use crate::heap::veneers::lazy_init_default_heap;

/// default_heap_free_bytes_get — original: `FUN_0807b180` @ `0x0807b180`
/// (24 bytes, including its literal).
///
/// Runs the default-heap lazy-initialization guard, then follows the existing
/// `DEFAULT_HEAP` seam (target global `0x089ca638`) and returns word zero of
/// the pointed-to descriptor — its raw `free_bytes` word. Both dereferences
/// have the raw ARM contract: the guard must leave a valid non-null handle
/// pointing to at least one readable word.
///
/// # Safety
///
/// The default-heap guard and global must satisfy that raw pointer contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn default_heap_free_bytes_get() -> u32 {
    lazy_init_default_heap();
    let default_heap = core::ptr::addr_of!(DEFAULT_HEAP).read();
    default_heap.cast::<u32>().read()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::sync::Mutex;
    use std::vec::Vec;

    use super::*;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::{HeapVeneerOps, HEAP_OPS};

    static GLOBALS_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: Vec<usize> = Vec::new();
    static mut CREATED_FREE_BYTES: u32 = 0x89ab_cdef;

    unsafe extern "C" fn recording_heap_create(
        _desc: *mut HeapDescriptor,
        _start: *mut u8,
        size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        (*core::ptr::addr_of_mut!(EVENTS)).push(size);
        core::ptr::addr_of_mut!(CREATED_FREE_BYTES).cast()
    }

    unsafe fn replace_default_heap(
        heap: *mut HeapDescriptorDescriptor,
    ) -> *mut HeapDescriptorDescriptor {
        let slot = core::ptr::addr_of_mut!(DEFAULT_HEAP);
        let old = slot.read();
        slot.write(heap);
        old
    }

    unsafe fn replace_heap_create(
        create: unsafe extern "C" fn(
            *mut HeapDescriptor,
            *mut u8,
            usize,
        ) -> *mut HeapDescriptorDescriptor,
    ) -> HeapVeneerOps {
        let old = core::ptr::read_volatile(core::ptr::addr_of!(HEAP_OPS));
        let mut ops = old;
        ops.create = create;
        core::ptr::addr_of_mut!(HEAP_OPS).write(ops);
        old
    }

    #[test]
    fn lazy_initialization_precedes_the_free_byte_load() {
        let _lock = GLOBALS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            let old_ops = replace_heap_create(recording_heap_create);
            let old_heap = replace_default_heap(core::ptr::null_mut());

            let result = default_heap_free_bytes_get();
            let events = (*core::ptr::addr_of!(EVENTS)).clone();

            replace_default_heap(old_heap);
            core::ptr::addr_of_mut!(HEAP_OPS).write(old_ops);

            assert_eq!(events, std::vec![0x8000]);
            assert_eq!(result, CREATED_FREE_BYTES);
        }
    }

    #[test]
    fn rereads_the_handle_and_returns_its_raw_first_word() {
        let _lock = GLOBALS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut first_free_bytes = 0u32;
        let mut second_free_bytes = u32::MAX;

        unsafe {
            let old_heap = replace_default_heap(core::ptr::addr_of_mut!(first_free_bytes).cast());
            let first_result = default_heap_free_bytes_get();
            replace_default_heap(core::ptr::addr_of_mut!(second_free_bytes).cast());
            let second_result = default_heap_free_bytes_get();
            replace_default_heap(old_heap);

            assert_eq!(first_result, first_free_bytes);
            assert_eq!(second_result, second_free_bytes);
        }
    }
}
