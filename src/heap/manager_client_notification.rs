//! `manager_client_notify` — `FUN_0818a41c` @ 0x0818a41c.
//! True extent: 60 bytes, ending at the next prologue at 0x0818a458.
//! Raw words verify two outgoing plain BLs, one BLEQ, and a tail B;
//! incoming calls are one plain BL (0x081fc27c) and one BLNE (0x081fbf58).
//!
//! Allocate 16 bytes, construct a type-three event carrying a client word,
//! panic on a NULL constructor result, and submit to manager+0x3c, returning
//! submission status unchanged. Deliberate deviations: the tail transfer is
//! a Rust call. The unported constructor at 0x08214270 remains resident on
//! ARM; host execution uses its decoded stores and the existing base port.

//! ARM match review: LLVM emits 18 instructions versus 15 stock, adding
//! a frame pointer and a constructor literal/BLX. Allocation, NULL/BLEQ
//! panic, manager+0x3c, and the final submission tail branch are preserved.
use crate::heap::veneers::{heap_panic, operator_new};
use crate::cxx::dispatch_item_submit::dispatch_item_submit;

#[inline(always)]
unsafe fn construct_client_event(storage: *mut u8, event: u32, client: u32) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let construct: unsafe extern "C" fn(*mut u8, u32, u32) -> *mut u8 =
            core::mem::transmute(0x0821_4270usize);
        construct(storage, event, client)
    }
    #[cfg(not(target_os = "none"))]
    {
        let node = crate::cxx::type_three_payload_construct::type_three_payload_construct(storage, event);
        node.cast::<u32>().write_volatile(0x0899_313c);
        node.cast::<u32>().add(3).write_volatile(client);
        node
    }
}

/// # Safety
/// `manager` must be a live block manager with a dispatch manager at +0x3c.
/// `client` is a target-width word; its referent must outlive queued use.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn manager_client_notify(manager: *mut u8, event: u32, client: u32) -> u32 {
    let storage = operator_new(16);
    let node = construct_client_event(storage, event, client);
    if node.is_null() { heap_panic(); }
    dispatch_item_submit(manager.add(0x3c), node)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_event_preserves_full_words_and_tag_padding() {
        for (event, client) in [(0, 0), (5, 0x8000_0000), (7, u32::MAX), (u32::MAX, 0x1234_5678)] {
            let mut words = [0xa5a5_a5a5u32; 6];
            let node = unsafe { words.as_mut_ptr().add(1).cast() };
            assert_eq!(unsafe { construct_client_event(node, event, client) }, node);
            assert_eq!(words, [0xa5a5_a5a5, 0x0899_313c, 0xa5a5_a503,
                event, client, 0xa5a5_a5a5]);
        }
    }
}
