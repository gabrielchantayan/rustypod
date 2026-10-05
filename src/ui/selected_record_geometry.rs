//! Selected indexed-record geometry refresh — FUN_0819ae74 @ 0x0819ae74.
//! True extent: 136 bytes, [0x0819ae74, 0x0819aefc); the next function
//! begins with an independent push at 0x0819aefc. Whole-image raw A32
//! decoding finds two inbound plain BLs (0x0819ae44, 0x0819af3c), zero
//! predicated BLs; the body has three plain BLs and zero predicated BLs.
//!
//! Look up the selected indexed record. If absent, leave the view untouched.
//! Otherwise copy its 48-byte geometry, replace words +8 and +20 with the
//! record's unsigned halfwords +14/+12 minus the view's x/y extents plus
//! 9/4, respectively, and apply the geometry with redraw enabled.
//! Deliberate deviations: reuse the existing Rust lookup, IRAM word-copy,
//! and geometry-setter ports. The receiver's pointer widens on hosts;
//! target offsets remain +0xb0/+0xb8. Arithmetic wraps like ARM SUB/ADD.

use core::ptr;
use crate::libc::iram_veneers::iram_memcpy_veneer;
use crate::ui::set_geometry::view_base_set_geometry;
use crate::ui::view_base::ViewBase;
use crate::util::indexed_record_lookup::indexed_record_lookup;

#[repr(C)]
pub struct SelectedRecordView {
    pub prefix: [u32; 0xb0 / 4],
    pub selected_index: u32,
    pub word_b4: u32,
    pub view: *mut ViewBase,
}

const _: [u8; 0xb0] = [0; core::mem::offset_of!(SelectedRecordView, selected_index)];
const _: [u8; 0xb8] = [0; core::mem::offset_of!(SelectedRecordView, view)];

#[inline(always)]
unsafe fn refresh_with_lookup(
    owner: *mut SelectedRecordView,
    lookup: impl FnOnce(u32) -> *mut u8,
) {
    let record = lookup(ptr::addr_of!((*owner).selected_index).read_volatile());
    if record.is_null() { return; }
    let view = ptr::addr_of!((*owner).view).read_volatile();
    let mut storage = core::mem::MaybeUninit::<[u32; 12]>::uninit();
    iram_memcpy_veneer(storage.as_mut_ptr().cast(), ptr::addr_of!((*view).geometry).cast(), 48);
    let geometry = &mut *storage.as_mut_ptr();
    let x_start = ptr::addr_of!((*view).bounds.x_start).read_volatile();
    let x_end = ptr::addr_of!((*view).bounds.x_end).read_volatile();
    geometry[2] = (record.add(14).cast::<u16>().read() as u32)
        .wrapping_sub(x_end.wrapping_sub(x_start)).wrapping_add(9);
    // Retail reloads the receiver's view pointer before reading y bounds.
    let y_view = ptr::addr_of!((*owner).view).read_volatile();
    let y_end = ptr::addr_of!((*y_view).bounds.y_end).read_volatile();
    let y_start = ptr::addr_of!((*y_view).bounds.y_start).read_volatile();
    geometry[5] = (record.add(12).cast::<u16>().read() as u32)
        .wrapping_sub(y_end.wrapping_sub(y_start)).wrapping_add(4);
    view_base_set_geometry(ptr::addr_of!((*owner).view).read_volatile(), geometry.as_ptr().cast(), 1);
}

/// Refreshes the selected record's view geometry and requests redraw.
/// The receiver must be valid; a non-null lookup result must provide aligned
/// halfwords through +14, and the receiver must then contain a live ViewBase.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn selected_record_view_refresh_geometry(owner: *mut SelectedRecordView) {
    refresh_with_lookup(owner, |index| indexed_record_lookup(index));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::set_geometry::{VIEW_BASE_GEOMETRY_CHANGED, VIEW_BASE_GEOMETRY_CHANGED_TEST_LOCK};
    use crate::ui::view_base::ViewBounds;

    unsafe extern "C" fn mark_redraw(view: *mut ViewBase) {
        (*view).flags |= 0x20;
    }

    #[test]
    fn missing_record_does_not_dereference_view() {
        let mut owner = SelectedRecordView {
            prefix: [0; 44], selected_index: 204, word_b4: 0, view: ptr::null_mut(),
        };
        unsafe { refresh_with_lookup(&mut owner, |_| ptr::null_mut()) };
        assert!(owner.view.is_null());
        assert_eq!(owner.selected_index, 204);
    }

    #[test]
    fn dimensions_preserve_geometry_and_wrap_signed_extents() {
        let _lock = VIEW_BASE_GEOMETRY_CHANGED_TEST_LOCK.lock().unwrap();
        struct Restore(crate::ui::set_geometry::ViewBaseGeometryChanged);
        impl Drop for Restore {
            fn drop(&mut self) { unsafe { VIEW_BASE_GEOMETRY_CHANGED = self.0; } }
        }
        let _restore = Restore(unsafe { VIEW_BASE_GEOMETRY_CHANGED });
        unsafe { VIEW_BASE_GEOMETRY_CHANGED = mark_redraw; }
        let cases = [
            (0u16, 0u16, [0, 0, 0, 0]),
            (100, 200, [10, 20, 40, 80]),
            (0, 0, [0, 0, 100, 200]),
            (65535, 32768, [u32::MAX, 0x80000000, 1, 0x7fffffff]),
        ];
        for (height, width, bounds) in cases {
            let mut view: ViewBase = unsafe { core::mem::zeroed() };
            let original: [u32; 12] = core::array::from_fn(|i| 0xa5000000 + i as u32);
            unsafe { ptr::copy_nonoverlapping(original.as_ptr().cast::<u8>(), view.geometry.as_mut_ptr(), 48); }
            view.bounds = ViewBounds { x_start: bounds[0], y_start: bounds[1], x_end: bounds[2], y_end: bounds[3] };
            let mut record = [0u16; 8];
            record[6] = height;
            record[7] = width;
            let mut owner = SelectedRecordView { prefix: [0; 44], selected_index: 7, word_b4: 0, view: &mut view };
            unsafe { refresh_with_lookup(&mut owner, |_| record.as_mut_ptr().cast()) };
            let mut expected = original;
            // Independent signed-wide reference, reduced to the ARM word.
            expected[2] = (width as i64 - (bounds[2] as i64 - bounds[0] as i64) + 9) as u32;
            expected[5] = (height as i64 - (bounds[3] as i64 - bounds[1] as i64) + 4) as u32;
            let actual = unsafe { ptr::read_unaligned(view.geometry.as_ptr().cast::<[u32; 12]>()) };
            assert_eq!(actual, expected);
            assert_eq!(view.flags, 0x20);
            assert_eq!(view.bounds, ViewBounds { x_start: bounds[0], y_start: bounds[1], x_end: bounds[2], y_end: bounds[3] });
        }
    }
}
