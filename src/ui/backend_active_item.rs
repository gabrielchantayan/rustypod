//! Resolve a UI backend's cached or flagged active `plst` item.

use super::plst_next::ui_plst_next;
use super::tdat_first_plst::ui_tdat_first_plst;

const CACHED_ITEM_OFFSET: usize = 0xf44;
const TDAT_ELEMENT_OFFSET: usize = 0xf60;
const ITEM_FLAGS_OFFSET: usize = 0x1ac;
const ACTIVE_ITEM_FLAG: u8 = 0x10;

/// ui_backend_active_item — original: `FUN_08054724` @ `0x08054724` (76
/// bytes; next real function starts at `0x08054770`; **3 plain `bl` callers
/// and no predicated-BL callers**, verified by decoding every B/BL word in
/// `osos.dec`).
///
/// Raw ARM runs from `push {r4,lr}` through `pop {r4,pc}`. It returns the
/// cached item at `backend + 0xf44` when nonzero. Otherwise it obtains the
/// first `plst` from the backend's `+0xf60` 'tdat' element, follows
/// `ui_plst_next`, and returns the first item whose `+0x1ac` flag has bit
/// `0x10`; it returns null at the end of the sequence.
///
/// Deliberate deviations: the two verified callees are invoked through their
/// direct Rust ports rather than stock addresses. The original's otherwise
/// unused `r4` save is omitted.
///
/// # Safety
///
/// `backend` must be readable through `+0xf63`. If its cached word is zero,
/// the `+0xf60` word must name an object satisfying
/// [`ui_tdat_first_plst`]'s requirements; every returned `plst` must satisfy
/// [`ui_plst_next`]'s requirements and be readable through `+0x1ac`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_backend_active_item")]
pub unsafe extern "C" fn ui_backend_active_item(backend: *const u8) -> *mut u8 {
    let cached = backend.add(CACHED_ITEM_OFFSET).cast::<u32>().read();
    if cached != 0 {
        return cached as usize as *mut u8;
    }

    let tdat = backend.add(TDAT_ELEMENT_OFFSET).cast::<u32>().read() as usize as *const u8;
    let mut item = ui_tdat_first_plst(tdat) as usize as *mut u8;
    while !item.is_null() {
        if item.add(ITEM_FLAGS_OFFSET).read() & ACTIVE_ITEM_FLAG != 0 {
            return item;
        }
        item = ui_plst_next(item) as usize as *mut u8;
    }
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const TDAT_TAG: u32 = 0x7464_6174;
    const PLST_TAG: u32 = 0x706c_7374;

    unsafe fn write_word(base: *mut u8, offset: usize, value: u32) {
        base.add(offset).cast::<u32>().write(value);
    }

    #[test]
    fn returns_cached_item_without_reading_the_fallback() {
        let Some(backend) = try_map_u32_slab(hints::BACKEND_ACTIVE_ITEM, 0x2000) else {
            assert!(note_missing_u32_fixture("ui/backend_active_item"));
            return;
        };
        unsafe {
            let cached = backend.add(0x1800);
            write_word(backend, CACHED_ITEM_OFFSET, cached as usize as u32);
            assert_eq!(ui_backend_active_item(backend), cached);
        }
    }

    #[test]
    fn returns_first_flagged_item_and_null_when_the_chain_has_no_match() {
        let Some(backend) = try_map_u32_slab(hints::BACKEND_ACTIVE_ITEM_CHAIN, 0x2000) else {
            assert!(note_missing_u32_fixture("ui/backend_active_item"));
            return;
        };
        unsafe {
            let tdat = backend.add(0x1000);
            let first = backend.add(0x1400);
            let second = backend.add(0x1800);
            write_word(backend, TDAT_ELEMENT_OFFSET, tdat as usize as u32);
            write_word(tdat, 4, TDAT_TAG);
            write_word(tdat, 0x34, first as usize as u32);
            write_word(first, 4, PLST_TAG);
            write_word(first, 0x24, second as usize as u32);
            write_word(second, 4, PLST_TAG);
            second.add(ITEM_FLAGS_OFFSET).write(ACTIVE_ITEM_FLAG);
            assert_eq!(ui_backend_active_item(backend), second);
            second.add(ITEM_FLAGS_OFFSET).write(0);
            assert!(ui_backend_active_item(backend).is_null());
        }
    }
}
