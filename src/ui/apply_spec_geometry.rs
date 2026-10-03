//! Apply an optional view specification's geometry and selected flags.
//!
//! `view_base_apply_spec_geometry` — FUN_0826e1e0 @ 0x0826e1e0.
//! True extent: 76 bytes (72 code + four-byte mask literal); next function
//! begins at 0x0826e22c. Raw A32 scan: two inbound plain BLs, zero
//! predicated BLs; one outbound plain BL, zero predicated BLs, and a tail
//! branch to view_base_geometry_changed at 0x0826db38.
//!
//! NULL spec returns without accessing the view. Otherwise forward-copy
//! 48 bytes from spec +0x1c to view +0x50, replace only flag bits selected
//! by 0x1eff8000 from spec +0x18, then notify geometry changed.
//! Deliberate deviations: the existing volatile geometry-changed dispatch
//! replaces the direct tail branch; its default is the actual Rust port.
//! Return is void, as in the callers; incidental r0 contents are not exposed.

use core::ptr;
use crate::libc::iram_veneers::iram_memcpy_veneer;
use crate::ui::set_geometry::VIEW_BASE_GEOMETRY_CHANGED;
use crate::ui::view_base::{ViewBase, ViewSpec};

const SPEC_FLAGS_MASK: u32 = 0x1eff8000;

/// # Safety
/// A non-NULL spec must be readable and word-aligned, and view must be a
/// writable ViewBase with valid linkage and virtual targets for redraw.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_base_apply_spec_geometry(view: *mut ViewBase, spec: *const ViewSpec) {
    if spec.is_null() { return; }
    iram_memcpy_veneer(
        ptr::addr_of_mut!((*view).geometry).cast(),
        ptr::addr_of!((*spec).geometry).cast(),
        0x30,
    );
    let incoming = ptr::addr_of!((*spec).flags).read();
    let flags = ptr::addr_of_mut!((*view).flags);
    flags.write((flags.read() & !SPEC_FLAGS_MASK) | (incoming & SPEC_FLAGS_MASK));
    let changed = ptr::addr_of!(VIEW_BASE_GEOMETRY_CHANGED).read_volatile();
    changed(view);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::set_geometry::VIEW_BASE_GEOMETRY_CHANGED_TEST_LOCK;

    struct Restore(crate::ui::set_geometry::ViewBaseGeometryChanged);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { VIEW_BASE_GEOMETRY_CHANGED = self.0; } }
    }

    unsafe extern "C" fn mark_dirty(view: *mut ViewBase) {
        (*view).flags |= 0x20;
    }

    #[test]
    fn null_spec_does_not_access_even_a_null_view() {
        unsafe { view_base_apply_spec_geometry(ptr::null_mut(), ptr::null()); }
    }

    #[test]
    fn replaces_each_selected_bit_preserves_others_and_copies_exact_geometry() {
        let _lock = match VIEW_BASE_GEOMETRY_CHANGED_TEST_LOCK.lock() {
            Ok(guard) => guard,
            Err(error) => panic!("geometry seam mutex poisoned: {error}"),
        };
        unsafe {
            let _restore = Restore(VIEW_BASE_GEOMETRY_CHANGED);
            VIEW_BASE_GEOMETRY_CHANGED = mark_dirty;
            for bit in 0..32 {
                for (old, incoming) in [(0, 1u32 << bit), (u32::MAX, !(1u32 << bit))] {
                    let mut view: ViewBase = core::mem::zeroed();
                    let mut spec: ViewSpec = core::mem::zeroed();
                    view.flags = old;
                    view.word_4c = 0x12345678;
                    view.bounds.x_start = 0x87654321;
                    spec.flags = incoming;
                    for i in 0..48 { spec.geometry[i] = (i as u8).wrapping_mul(7); }
                    view_base_apply_spec_geometry(&mut view, &spec);
                    let mut expected = old;
                    for b in 0..32 {
                        let mask = 1u32 << b;
                        if SPEC_FLAGS_MASK & mask != 0 {
                            expected = (expected & !mask) | (incoming & mask);
                        }
                    }
                    assert_eq!(view.flags, expected | 0x20);
                    assert_eq!(view.geometry, spec.geometry);
                    assert_eq!(view.word_4c, 0x12345678);
                    assert_eq!(view.bounds.x_start, 0x87654321);
                    assert_eq!(spec.flags, incoming);
                }
            }
        }
    }
}
