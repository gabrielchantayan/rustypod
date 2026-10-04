//! `media_player_selector_update` — `FUN_081feb78` @ **0x081feb78**.
//! True extent: **136 bytes**, `0x081feb78..0x081fec00`; the next raw ARM
//! function starts with a push at 0x081fec00. Three unconditional direct BLs,
//! zero predicated BLs, two unconditional virtual BLX calls; two direct callers.
//!
//! Reject unsigned selectors >= 3 with error 4 before obtaining the interface.
//! Otherwise clear callback slot 7 when register_callback is zero, or query
//! vtable +0x48 and register {callback_kind, query_result, 0}. Always invoke
//! vtable +0x44 with the selector afterward, ignoring slot-helper results and
//! returning zero. Virtual target identities remain unresolved.
//!
//! Deliberate deviations: reuse the ported singleton getter and slot table
//! (whose storage is crate-owned rather than retail RAM). Host vtable fixtures
//! use native pointer-width words and a getter seam; ARM words remain 4 bytes.

use crate::app::slot_table::{slot_table_clear, slot_table_register};

const SELECTOR_SLOT: usize = 0x44 / 4;
const QUERY_SLOT: usize = 0x48 / 4;
type Query = unsafe extern "C" fn(*mut u8) -> u32;
type SetSelector = unsafe extern "C" fn(*mut u8, u32);

#[cfg(not(target_os = "none"))]
pub static mut GET_INTERFACE: unsafe extern "C" fn() -> *mut u8 = missing_interface;
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_interface() -> *mut u8 { core::ptr::null_mut() }

unsafe fn interface() -> *mut u8 {
    #[cfg(target_os = "none")]
    { super::singletons::media_player_interface_get() }
    #[cfg(not(target_os = "none"))]
    { core::ptr::read_volatile(core::ptr::addr_of!(GET_INTERFACE))() }
}

unsafe fn vtable_word(interface: *mut u8, index: usize) -> usize {
    let vtable = interface.cast::<*const usize>().read_volatile();
    vtable.add(index).read_volatile()
}

/// Updates selector and callback slot 7, preserving retail call order.
///
/// # Safety
/// For selector < 3 the getter must return a valid vtable-bearing interface
/// with callable +0x44/+0x48 entries. `this` is not dereferenced by slot helpers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_player_selector_update(
    this: *mut u8, selector: u32, register_callback: i32, callback_kind: i32,
) -> u32 {
    if selector >= 3 { return 4; }
    let media = interface();
    if register_callback == 0 {
        slot_table_clear(this, 7);
    } else {
        let query: Query = core::mem::transmute(vtable_word(media, QUERY_SLOT));
        let value = query(media);
        slot_table_register(this, 7, callback_kind, value, 0);
    }
    // Reload the vtable after the query and table update, as retail does.
    let set: SetSelector = core::mem::transmute(vtable_word(media, SELECTOR_SLOT));
    set(media, selector);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::slot_table::{Slot, SLOTS, SLOT_KIND_FREE};
    use core::ptr;

    #[repr(C)]
    struct Media { vtable: *const usize, current: u32, queries: u32, sets: u32,
        expected_kind: i32, expected_value: u32, expected_occupied: u8 }
    static mut MEDIA: *mut Media = ptr::null_mut();
    unsafe extern "C" fn get() -> *mut u8 { MEDIA.cast() }
    unsafe extern "C" fn query(media: *mut u8) -> u32 {
        let media = &mut *media.cast::<Media>();
        media.queries += 1;
        media.current
    }
    unsafe fn slot() -> *mut Slot { ptr::addr_of_mut!(SLOTS).cast::<Slot>().add(7) }
    unsafe extern "C" fn set(media: *mut u8, selector: u32) {
        let media = &mut *media.cast::<Media>();
        // Consumer-visible ordering: callback data is ready before dispatch.
        assert_eq!((*slot()).occupied, media.expected_occupied);
        assert_eq!((*slot()).kind, media.expected_kind);
        assert_eq!((*slot()).value_a, media.expected_value);
        assert_eq!((*slot()).value_b, 0);
        media.current = selector;
        media.sets += 1;
    }

    #[test]
    fn boundaries_registration_clear_and_ignored_errors() {
        let _guard = crate::app::slot_table::tests::SLOTS_LOCK.lock()
            .unwrap_or_else(|error| error.into_inner());
        unsafe {
            let previous_get = GET_INTERFACE;
            let previous_slot = ptr::read(slot());
            let mut vtable = [0usize; QUERY_SLOT + 1];
            vtable[SELECTOR_SLOT] = set as *const () as usize;
            vtable[QUERY_SLOT] = query as *const () as usize;
            let mut media = Media { vtable: vtable.as_ptr(), current: 0xfedc_ba98,
                queries: 0, sets: 0, expected_kind: -1, expected_value: 0xfedc_ba98,
                expected_occupied: 1 };
            MEDIA = &mut media;
            GET_INTERFACE = get;
            slot_table_clear(ptr::null_mut(), 7);
            for selector in [3, 4, u32::MAX] {
                assert_eq!(media_player_selector_update(ptr::null_mut(), selector, 1, 0), 4);
                assert_eq!((*slot()).occupied, 0);
            }
            assert_eq!((media.queries, media.sets), (0, 0));
            assert_eq!(media_player_selector_update(ptr::null_mut(), 2, -1, -1), 0);
            assert_eq!((media.current, media.queries, media.sets), (2, 1, 1));
            // Occupied slots are preserved, but querying and setting still happen.
            assert_eq!(media_player_selector_update(ptr::null_mut(), 2, 1, 2), 0);
            assert_eq!((media.queries, media.sets), (2, 2));
            media.expected_kind = SLOT_KIND_FREE;
            media.expected_value = 0;
            media.expected_occupied = 0;
            assert_eq!(media_player_selector_update(ptr::null_mut(), 0, 0, 99), 0);
            assert_eq!((media.current, media.queries, media.sets), (0, 2, 3));
            // Registrar error 9 is ignored, selector dispatch still succeeds.
            assert_eq!(media_player_selector_update(ptr::null_mut(), 1, 1, 3), 0);
            assert_eq!((media.current, media.queries, media.sets), (1, 3, 4));
            ptr::write(slot(), previous_slot);
            GET_INTERFACE = previous_get;
            MEDIA = ptr::null_mut();
        }
    }
}
