//! `media_player_slot_5c_selector_update` — `FUN_082006dc` @ **0x082006dc**.
//! True extent: **180 bytes**, ending before the prologue at 0x08200790.
//! Raw words: three unconditional direct BLs, zero predicated BLs, one BLX
//! and one BLXNE; two incoming unconditional BLs, zero predicated callers.
//!
//! Reject unsigned selectors 4..=252 with error 4. Normalize 2/3 to 1 and
//! 253/254 to 255; other accepted words pass through (including >255).
//! Query vtable +0x60, then clear callback slot 14 for a zero registration
//! flag or register {callback_kind, old_value, 0}. Ignore helper results.
//! If old_value differs, reload the vtable and call +0x5c with the normalized
//! selector. Return zero. Virtual target identities remain unresolved.
//!
//! Deliberate deviations: reuse the singleton getter (including its existing
//! NOT-HOOK-READY constructor caveat) and crate-owned slot table, not retail
//! RAM. Host fixtures use native-width vtable words and a getter seam;
//! target words remain four bytes.

use crate::app::slot_table::{slot_table_clear, slot_table_register};

const SELECTOR_SLOT: usize = 0x5c / 4;
const QUERY_SLOT: usize = 0x60 / 4;
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

/// Updates the normalized +0x5c selector and callback slot 14 in retail order.
///
/// # Safety
/// For accepted selectors the getter must return a valid vtable-bearing
/// interface with callable +0x60/+0x5c entries. Slot helpers do not read `this`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_player_slot_5c_selector_update(
    this: *mut u8, selector: u32, register_callback: i32, callback_kind: i32,
) -> u32 {
    if selector > 3 && selector < 253 { return 4; }
    let media = interface();
    let selector = match selector { 2 | 3 => 1, 253 | 254 => 255, value => value };
    let query: Query = core::mem::transmute(vtable_word(media, QUERY_SLOT));
    let previous = query(media);
    if register_callback == 0 {
        slot_table_clear(this, 14);
    } else {
        slot_table_register(this, 14, callback_kind, previous, 0);
    }
    if previous != selector {
        let set: SetSelector = core::mem::transmute(vtable_word(media, SELECTOR_SLOT));
        set(media, selector);
    }
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
        queries: u32, sets: u32, expected: Slot,
    }
    static mut MEDIA: *mut Media = ptr::null_mut();
    unsafe extern "C" fn get() -> *mut u8 { MEDIA.cast() }
    unsafe extern "C" fn forbidden_get() -> *mut u8 { panic!("invalid selector accessed interface") }
    unsafe fn slot() -> *mut Slot { ptr::addr_of_mut!(SLOTS).cast::<Slot>().add(14) }
    unsafe extern "C" fn query(media: *mut u8) -> u32 {
        let media = &mut *media.cast::<Media>();
        media.queries += 1;
        media.vtable = media.replacement;
        media.current
    }
    unsafe extern "C" fn forbidden_set(_: *mut u8, _: u32) { panic!("stale vtable dispatch") }
    unsafe extern "C" fn set(media: *mut u8, selector: u32) {
        let media = &mut *media.cast::<Media>();
        assert_eq!((*slot()).occupied, media.expected.occupied);
        assert_eq!((*slot()).kind, media.expected.kind);
        assert_eq!((*slot()).value_a, media.expected.value_a);
        assert_eq!((*slot()).value_b, media.expected.value_b);
        media.current = selector;
        media.sets += 1;
    }

    #[test]
    fn normalization_unsigned_bounds_and_callback_transitions() {
        let _guard = crate::app::slot_table::tests::SLOTS_LOCK.lock()
            .unwrap_or_else(|error| error.into_inner());
        unsafe {
            let previous_get = GET_INTERFACE;
            let previous_slot = ptr::read(slot());
            GET_INTERFACE = forbidden_get;
            for selector in 4..=252 {
                assert_eq!(media_player_slot_5c_selector_update(ptr::null_mut(), selector, 1, 0), 4);
            }
            let mut vtable = [0usize; QUERY_SLOT + 1];
            vtable[SELECTOR_SLOT] = set as *const () as usize;
            vtable[QUERY_SLOT] = query as *const () as usize;
            let mut original = vtable;
            original[SELECTOR_SLOT] = forbidden_set as *const () as usize;
            let mut media = Media { vtable: original.as_ptr(), replacement: vtable.as_ptr(),
                current: 42, queries: 0, sets: 0,
                expected: Slot { occupied: 0, reserved: [0; 3], kind: SLOT_KIND_FREE, value_a: 0, value_b: 0 } };
            MEDIA = &mut media;
            GET_INTERFACE = get;
            for (requested, normalized) in [(0, 0), (1, 1), (2, 1), (3, 1),
                (253, 255), (254, 255), (255, 255), (256, 256),
                (0x8000_0000, 0x8000_0000), (u32::MAX, u32::MAX)] {
                media.current = 42;
                media.vtable = original.as_ptr();
                assert_eq!(media_player_slot_5c_selector_update(ptr::null_mut(), requested, 0, 99), 0);
                assert_eq!(media.current, normalized);
            }
            assert_eq!((media.queries, media.sets), (10, 10));
            // Query and registration still happen when normalization suppresses dispatch.
            media.current = 1;
            assert_eq!(media_player_slot_5c_selector_update(ptr::null_mut(), 3, -1, -1), 0);
            assert_eq!((media.queries, media.sets), (11, 10));
            assert_eq!(((*slot()).occupied, (*slot()).kind, (*slot()).value_a, (*slot()).value_b), (1, -1, 1, 0));
            media.expected = ptr::read(slot());
            assert_eq!(media_player_slot_5c_selector_update(ptr::null_mut(), 254, 1, 2), 0);
            assert_eq!(media.current, 255); // Busy registration preserves old callback.
            media.expected = Slot { occupied: 0, reserved: [0; 3], kind: SLOT_KIND_FREE, value_a: 0, value_b: 0 };
            assert_eq!(media_player_slot_5c_selector_update(ptr::null_mut(), 255, 0, 0), 0);
            assert_eq!((*slot()).occupied, 0); // Clear even when selector is unchanged.
            assert_eq!(media_player_slot_5c_selector_update(ptr::null_mut(), 0, 1, 3), 0);
            assert_eq!(media.current, 0); // Invalid kind does not prevent dispatch.
            assert_eq!((media.queries, media.sets), (14, 12));
            ptr::write(slot(), previous_slot);
            GET_INTERFACE = previous_get;
            MEDIA = ptr::null_mut();
        }
    }
}
