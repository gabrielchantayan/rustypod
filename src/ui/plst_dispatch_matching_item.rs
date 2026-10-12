//! Dispatch one matching playlist slot item — retailOS `FUN_08046180`
//! at 0x08046180, 184 bytes, extent [0x08046180, 0x08046238).
//! Raw ARM: two inbound plain BLs, six outbound plain BLs, zero predicated BLs.
//! Resolve the backend, retain its +0xf60 element, scan the playlist's u16
//! count, and dispatch the zero-based requested match. Exhaustion or dispatch
//! releases the backend's current +0xf60 element; a null slot deliberately
//! returns WITHOUT release. Negative ordinals are unsigned countdowns.
//! Deviations: Rust ports replace known callees; the unported item-state
//! refresh predicate at 0x080e28c4 remains a firmware call / explicit host seam.
//! Only its r0 result is consumed; incidental r1/r3 values are not ABI inputs.

pub type RefreshItemMatch = unsafe extern "C" fn(*const u8, u32, u32) -> u32;

#[cfg(target_arch = "arm")]
unsafe extern "C" {
    fn dispatch_if_optional_link_valid(node: *const u32, dispatcher: u32, link: *mut u32, value: u32) -> u32;
}
#[cfg(not(target_arch = "arm"))]
use crate::util::dispatch_if_optional_link_valid::dispatch_if_optional_link_valid;

#[cfg(not(target_os = "none"))]
pub static mut PLST_REFRESH_ITEM_MATCH: Option<RefreshItemMatch> = None;

unsafe fn refresh_item_match(object: *const u8, item: u32) -> u32 {
    #[cfg(target_os = "none")]
    let refresh: RefreshItemMatch = core::mem::transmute(0x080e_28c4usize);
    #[cfg(not(target_os = "none"))]
    let refresh = core::ptr::read_volatile(core::ptr::addr_of!(PLST_REFRESH_ITEM_MATCH))
        .expect("install retail item-match refresh seam");
    refresh(object, item, 0)
}

#[inline(always)]
fn dispatch_matching_item(
    count: u32,
    mut ordinal: u32,
    mut item_at: impl FnMut(u32) -> u32,
    mut matches: impl FnMut(u32) -> bool,
    mut dispatch: impl FnMut(u32),
    mut release: impl FnMut(),
) {
    for index in 0..count {
        let item = item_at(index);
        if item == 0 {
            return;
        }
        if matches(item) {
            if ordinal == 0 {
                dispatch(item);
                break;
            }
            ordinal = ordinal.wrapping_sub(1);
        }
    }
    release();
}

/// # Safety
/// Object must support backend resolution and the +0xf60 word. A non-null
/// playlist must have a valid 32-bit header link at +0x40, readable through
/// +0x2f. Slot items and dispatcher must satisfy the retail callee contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn plst_dispatch_matching_item(
    object: *const u8,
    playlist: *mut u8,
    selector: u32,
    reverse_flag: u32,
    ordinal: u32,
    dispatcher: u32,
) {
    let backend = crate::ui::object_state::object_backend_for_kind(object);
    let count = if playlist.is_null() { 0 } else {
        let header = playlist.add(0x40).cast::<u32>().read() as usize as *const u8;
        u32::from(header.add(0x2e).cast::<u16>().read())
    };
    let retained = backend.add(0xf60).cast::<u32>().read() as usize as *mut u8;
    crate::ui::tdat_counter_addrefs::tdat_element_addref_counters(retained);
    dispatch_matching_item(
        count, ordinal,
        |index| crate::ui::plst_slot_item::ui_plst_slot_item_at(playlist, selector, reverse_flag, index),
        |item| refresh_item_match(object, item) != 0,
        |item| { dispatch_if_optional_link_valid(
            item as usize as *const u32, dispatcher, core::ptr::null_mut(), 0); },
        || {
            let current = backend.add(0xf60).cast::<u32>().read() as usize as *mut u8;
            crate::ui::tdat_counter_releases::tdat_element_release_counters(current);
        },
    );
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::cell::Cell;
    use std::vec::Vec;

    #[test]
    fn ordinal_counts_matches_not_slots_and_stops_at_dispatch() {
        for ordinal in [0, 1, 2, 3, u32::MAX, 0x8000_0000] {
            let items = [2, 3, 4, 5, 7, 9];
            let mut visited = Vec::new();
            let mut selected = None;
            let refs = Cell::new(2);
            dispatch_matching_item(6, ordinal,
                |i| { visited.push(i); items[i as usize] },
                |item| item & 1 != 0,
                |item| selected = Some(item),
                || refs.set(refs.get() - 1));
            let expected = [3, 5, 7, 9].get(ordinal as usize).copied();
            assert_eq!(selected, expected);
            let last = expected.map(|v| items.iter().position(|&x| x == v).unwrap()).unwrap_or(5);
            assert_eq!(visited, (0..=last as u32).collect::<Vec<_>>());
            assert_eq!(refs.get(), 1);
        }
    }

    #[test]
    fn empty_exhausted_and_null_slot_have_distinct_release_behavior() {
        for (items, ordinal, released) in [
            (&[][..], 0, true), (&[2, 4][..], 0, true),
            (&[3, 0, 5][..], 1, false), (&[0][..], 0, false),
            (&[3, 0][..], 0, true),
        ] {
            let refs = Cell::new(2);
            let mut selected = None;
            dispatch_matching_item(items.len() as u32, ordinal,
                |i| items[i as usize], |item| item & 1 != 0,
                |item| selected = Some(item), || refs.set(refs.get() - 1));
            assert_eq!(refs.get(), if released { 1 } else { 2 });
            assert_eq!(selected, if items == [3, 0] && ordinal == 0 { Some(3) } else { None });
        }
    }
}
