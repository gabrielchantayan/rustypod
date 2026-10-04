//! `media_player_slot_3c_selector_update` — `FUN_081fe9cc` @ **0x081fe9cc**.
//! True extent: **136 bytes**, ending at the next function at 0x081fea54.
//! Raw words: three unconditional direct BLs, zero predicated BLs, two
//! unconditional virtual BLX calls; two incoming unconditional BLs.
//!
//! Reject unsigned selectors >= 3 with error 4 before getting the interface.
//! Otherwise clear callback slot 8 for a zero registration flag, or query
//! vtable +0x40 and register {callback_kind, query_result, 0}. Reload the
//! vtable and dispatch +0x3c with selector even if registration failed or the
//! selector is unchanged. Ignore helper results and return zero.
//!
//! Deliberate deviations: reuse the existing singleton getter (including its
//! NOT-HOOK-READY constructor caveat) and crate-owned slot table rather than
//! retail RAM. Host vtables use native-width words and a getter seam; target
//! words remain four bytes. Virtual target identities are unresolved.

use crate::app::slot_table::{slot_table_clear, slot_table_register};

const SELECTOR_SLOT: usize = 0x3c / 4;
const QUERY_SLOT: usize = 0x40 / 4;
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

/// Updates the +0x3c selector and callback slot 8 in retail call order.
///
/// # Safety
/// For selector < 3 the getter must return a valid vtable-bearing interface
/// with callable +0x3c/+0x40 entries. `this` is not read by the slot helpers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_player_slot_3c_selector_update(
    this: *mut u8, selector: u32, register_callback: i32, callback_kind: i32,
) -> u32 {
    if selector >= 3 { return 4; }
    let media = interface();
    if register_callback == 0 {
        slot_table_clear(this, 8);
    } else {
        let query: Query = core::mem::transmute(vtable_word(media, QUERY_SLOT));
        let value = query(media);
        slot_table_register(this, 8, callback_kind, value, 0);
    }
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
    struct Media {
        vtable: *const usize, replacement: *const usize, current: u32,
        queries: u32, sets: u32, expected_kind: i32,
        expected_value: u32, expected_occupied: u8,
    }
    static mut MEDIA: *mut Media = ptr::null_mut();
    unsafe extern "C" fn get() -> *mut u8 { MEDIA.cast() }
    unsafe extern "C" fn forbidden_get() -> *mut u8 { panic!("invalid selector accessed interface") }
    unsafe extern "C" fn query(media: *mut u8) -> u32 {
        let media = &mut *media.cast::<Media>();
        media.queries += 1;
        media.vtable = media.replacement;
        media.current
    }
    unsafe fn slot() -> *mut Slot { ptr::addr_of_mut!(SLOTS).cast::<Slot>().add(8) }
    unsafe extern "C" fn forbidden_set(_: *mut u8, _: u32) { panic!("stale vtable dispatch") }
    unsafe extern "C" fn set(media: *mut u8, selector: u32) {
        let media = &mut *media.cast::<Media>();
        assert_eq!((*slot()).occupied, media.expected_occupied);
        assert_eq!((*slot()).kind, media.expected_kind);
        assert_eq!((*slot()).value_a, media.expected_value);
        assert_eq!((*slot()).value_b, 0);
        media.current = selector;
        media.sets += 1;
    }

    #[test]
    fn unsigned_bounds_callback_lifecycle_errors_and_vtable_reload() {
        let _guard = crate::app::slot_table::tests::SLOTS_LOCK.lock()
            .unwrap_or_else(|error| error.into_inner());
        unsafe {
            let previous_get = GET_INTERFACE;
            let previous_slot = ptr::read(slot());
            GET_INTERFACE = forbidden_get;
            for selector in [3, 4, 0x8000_0000, u32::MAX] {
                assert_eq!(media_player_slot_3c_selector_update(ptr::null_mut(), selector, 1, 0), 4);
            }
            let mut vtable = [0usize; QUERY_SLOT + 1];
            vtable[SELECTOR_SLOT] = set as *const () as usize;
            vtable[QUERY_SLOT] = query as *const () as usize;
            let mut original = vtable;
            original[SELECTOR_SLOT] = forbidden_set as *const () as usize;
            let mut media = Media { vtable: original.as_ptr(), replacement: vtable.as_ptr(),
                current: 0xfedc_ba98, queries: 0, sets: 0, expected_kind: -1,
                expected_value: 0xfedc_ba98, expected_occupied: 1 };
            MEDIA = &mut media;
            GET_INTERFACE = get;
            slot_table_clear(ptr::null_mut(), 8);
            assert_eq!(media_player_slot_3c_selector_update(ptr::null_mut(), 2, -1, -1), 0);
            assert_eq!((media.current, media.queries, media.sets), (2, 1, 1));
            // Busy registration preserves the old callback, but still queries
            // and dispatches even for an unchanged selector.
            assert_eq!(media_player_slot_3c_selector_update(ptr::null_mut(), 2, 1, 2), 0);
            assert_eq!((media.current, media.queries, media.sets), (2, 2, 2));
            media.expected_kind = SLOT_KIND_FREE;
            media.expected_value = 0;
            media.expected_occupied = 0;
            assert_eq!(media_player_slot_3c_selector_update(ptr::null_mut(), 0, 0, 99), 0);
            assert_eq!((media.current, media.queries, media.sets), (0, 2, 3));
            // Invalid kind fails registration without preventing selector update.
            assert_eq!(media_player_slot_3c_selector_update(ptr::null_mut(), 1, 1, 3), 0);
            assert_eq!((media.current, media.queries, media.sets), (1, 3, 4));
            ptr::write(slot(), previous_slot);
            GET_INTERFACE = previous_get;
            MEDIA = ptr::null_mut();
        }
    }
}
