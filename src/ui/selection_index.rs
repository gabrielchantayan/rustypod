//! Selection-index update for a UI element whose enclosing derived layout is
//! not yet recovered.
//!
//! `ui_element_set_selection_index` — original: `FUN_081ea758` @
//! **0x081ea758** (16 bytes, `0x081ea758..0x081ea764`; the separate sibling
//! begins at `0x081ea768`).
//!
//! The raw body stores `selection_index` at `element + 0x124`, writes one to
//! the change byte at `element + 0x120`, then tail-branches to
//! [`crate::ui::invalidate::ui_element_invalidate`]. It therefore returns the
//! original element pointer restored by that invalidation path.
//!
//! Decoding every ARM B/BL word in `osos.dec` finds 10 direct call sites: two
//! unconditional `bl`, seven `blne`, and one `blcs`; there are no direct tail
//! `b` or image-word references. The seven `blne` callers have already checked
//! the nullable element lookup. The `blcs` at `0x081ea7c4` clamps this index to
//! an element-owned count before updating it. Ghidra incorrectly absorbs the
//! sibling at `0x081ea768` into this function.
//!
//! Deliberate deviations: none. The enclosing derived element type remains
//! unrecovered, so this module models only the verified field prefix rather
//! than assigning the object a speculative class identity.

use core::ptr;

#[repr(C)]
struct IndexedElementLayout {
    /// Opaque fields through `+0x11f`.
    prefix: [u8; 0x120],
    /// `+0x120` — set to one after every selection-index update.
    selection_changed: u8,
    /// `+0x121..+0x123` — alignment before the target word.
    padding: [u8; 3],
    /// `+0x124` — current selection index.
    selection_index: u32,
}

const _: [u8; 0x128] = [0; core::mem::size_of::<IndexedElementLayout>()];
const _: [u8; 0x120] = [0; core::mem::offset_of!(IndexedElementLayout, selection_changed)];
const _: [u8; 0x124] = [0; core::mem::offset_of!(IndexedElementLayout, selection_index)];

/// Stores an element's selection index, marks that selection changed, and
/// invalidates the entire element.
///
/// # Safety
///
/// `element` must point to a writable instance with this verified field
/// layout; it is immediately passed to `ui_element_invalidate`, so its UI
/// element prefix must also be valid for that function.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_element_set_selection_index(
    element: *mut u8,
    selection_index: u32,
) -> *mut u8 {
    let layout = element.cast::<IndexedElementLayout>();
    unsafe {
        ptr::addr_of_mut!((*layout).selection_index).write_volatile(selection_index);
        ptr::addr_of_mut!((*layout).selection_changed).write_volatile(1);
        crate::ui::invalidate::ui_element_invalidate(element)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(index: u32, changed: u8) -> IndexedElementLayout {
        IndexedElementLayout {
            prefix: [0; 0x120],
            selection_changed: changed,
            padding: [0; 3],
            selection_index: index,
        }
    }

    #[test]
    fn updates_first_selection_and_marks_change() {
        let mut element = fixture(u32::MAX, 0);
        let pointer = core::ptr::addr_of_mut!(element).cast();

        let returned = unsafe { ui_element_set_selection_index(pointer, 0) };

        assert_eq!(returned, pointer);
        assert_eq!(element.selection_index, 0);
        assert_eq!(element.selection_changed, 1);
    }

    #[test]
    fn overwrites_full_width_index_and_marks_repeated_update() {
        let mut element = fixture(7, 0xff);
        let pointer = core::ptr::addr_of_mut!(element).cast();

        unsafe { ui_element_set_selection_index(pointer, u32::MAX) };
        element.selection_changed = 0;
        unsafe { ui_element_set_selection_index(pointer, u32::MAX) };

        assert_eq!(element.selection_index, u32::MAX);
        assert_eq!(element.selection_changed, 1);
    }
}
