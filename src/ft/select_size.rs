//! FreeType fixed bitmap strike selection.

use core::ffi::c_void;
use crate::ft::face::FtDriver;
use crate::ft::glyph_slot::{FtDriverClass, FtFace};
use crate::ft::select_metrics::{ft_select_metrics, FtSizeRec};

/// Driver class extension through `select_size` (+0x5c on ARM).
/// The existing prefix ends at `done_slot` (+0x44); the intervening
/// callbacks are load_glyph, get_kerning, attach_file, get_advances,
/// and request_size. Pointer fields widen together on hosts.
#[repr(C)]
struct FtStrikeDriverClass {
    prefix: FtDriverClass,
    preceding_callbacks: [*const c_void; 5],
    select_size: Option<unsafe extern "C" fn(*mut FtSizeRec, u32) -> i32>,
}

/// `FT_Select_Size` — original `FUN_0804ebac`, load address 0x0804ebac,
/// true size 84 bytes (next function begins at 0x0804ec00).
/// Raw ARM words verify two plain incoming BLs (0x0804ea2c, 0x0808f368),
/// zero predicated incoming BLs, one plain outgoing BL to ft_select_metrics
/// (0x0804ebf4), and zero predicated outgoing BLs. A BXNE tail-dispatches
/// the driver's select_size callback with face->size and the strike index.
///
/// Reject null/non-fixed-size faces with 0x23, then reject negative indices
/// or indices >= the signed num_fixed_sizes with 6. Return the driver's
/// callback result unchanged when present; otherwise select bitmap metrics
/// via the existing port and return zero. Deliberate deviation: Rust may
/// emit an indirect call rather than the retail conditional tail BX.
///
/// # Safety
/// Non-null face must be readable. After validation its driver and class
/// must be valid; its size and strike descriptors must satisfy the chosen
/// callback or ft_select_metrics contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_select_size(face: *mut FtFace, strike_index: i32) -> i32 {
    if face.is_null() || (*face).face_flags & 2 == 0 {
        return 0x23;
    }
    if strike_index < 0 || (*face).num_fixed_sizes <= strike_index {
        return 6;
    }
    let driver = (*face).driver.cast::<FtDriver>();
    let class = (*driver).clazz.cast::<FtStrikeDriverClass>();
    if let Some(select_size) = (*class).select_size {
        return select_size((*face).size.cast(), strike_index as u32);
    }
    ft_select_metrics(face, strike_index as u32);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ft::select_metrics::FtBitmapSize;

    #[test]
    fn invalid_faces_and_signed_index_boundaries_do_not_access_driver() {
        unsafe {
            assert_eq!(ft_select_size(core::ptr::null_mut(), -1), 0x23);
            let mut face: FtFace = core::mem::zeroed();
            face.num_fixed_sizes = 2;
            assert_eq!(ft_select_size(&mut face, 0), 0x23);
            face.face_flags = 2;
            for index in [i32::MIN, -1, 2, i32::MAX] {
                assert_eq!(ft_select_size(&mut face, index), 6);
            }
            for count in [i32::MIN, -1, 0] {
                face.num_fixed_sizes = count;
                assert_eq!(ft_select_size(&mut face, 0), 6);
            }
        }
    }

    unsafe extern "C" fn select_strike(size: *mut FtSizeRec, index: u32) -> i32 {
        (*size).metrics.height = 100 + index as i32;
        -73
    }

    #[test]
    fn driver_selection_changes_active_size_and_preserves_error() {
        unsafe {
            let mut class: FtStrikeDriverClass = core::mem::zeroed();
            class.select_size = Some(select_strike);
            let mut driver: FtDriver = core::mem::zeroed();
            driver.clazz = &class.prefix;
            let mut size: FtSizeRec = core::mem::zeroed();
            let mut face: FtFace = core::mem::zeroed();
            face.face_flags = 2;
            face.num_fixed_sizes = 2;
            face.driver = (&mut driver as *mut FtDriver).cast();
            face.size = (&mut size as *mut FtSizeRec).cast();
            assert_eq!(ft_select_size(&mut face, 0), -73);
            assert_eq!(size.metrics.height, 100);
            assert_eq!(ft_select_size(&mut face, 1), -73);
            assert_eq!(size.metrics.height, 101);
        }
    }

    #[test]
    fn missing_driver_callback_selects_requested_bitmap_metrics() {
        unsafe {
            let class: FtStrikeDriverClass = core::mem::zeroed();
            let mut driver: FtDriver = core::mem::zeroed();
            driver.clazz = &class.prefix;
            let mut size: FtSizeRec = core::mem::zeroed();
            let mut strikes = [
                FtBitmapSize { height: 9, width: 8, size: 0, x_ppem: 8 << 6, y_ppem: 9 << 6 },
                FtBitmapSize { height: 17, width: 14, size: 0, x_ppem: (14 << 6) + 32, y_ppem: 17 << 6 },
            ];
            let mut face: FtFace = core::mem::zeroed();
            face.face_flags = 2;
            face.num_fixed_sizes = 2;
            face.driver = (&mut driver as *mut FtDriver).cast();
            face.size = (&mut size as *mut FtSizeRec).cast();
            face.available_sizes = strikes.as_mut_ptr().cast();
            assert_eq!(ft_select_size(&mut face, 1), 0);
            assert_eq!((size.metrics.x_ppem, size.metrics.y_ppem), (15, 17));
            assert_eq!((size.metrics.x_scale, size.metrics.y_scale), (0x400000, 0x400000));
            assert_eq!((size.metrics.ascender, size.metrics.descender), (17 << 6, 0));
            assert_eq!(size.metrics.height, 17 << 6);
            assert_eq!(size.metrics.max_advance, (14 << 6) + 32);
        }
    }
}
