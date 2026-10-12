//! FreeType size-request validation and driver dispatch.

use core::ffi::c_void;
use crate::ft::face::FtDriver;
use crate::ft::glyph_slot::{FtDriverClass, FtFace};
use crate::ft::select_metrics::FtSizeRec;
use crate::ft::select_size::ft_select_size;
use crate::ft::size::FtSizeRequest;

#[repr(C)]
struct FtRequestDriverClass {
    prefix: FtDriverClass,
    preceding_callbacks: [*const c_void; 4],
    request_size: Option<unsafe extern "C" fn(*mut FtSizeRec, *const FtSizeRequest) -> i32>,
}

type MatchSize = unsafe extern "C" fn(*mut FtFace, *const FtSizeRequest, i32, *mut i32) -> i32;
type RequestMetrics = unsafe extern "C" fn(*mut FtFace, *const FtSizeRequest);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_match_size(_: *mut FtFace, _: *const FtSizeRequest, _: i32, _: *mut i32) -> i32 {
    panic!("install stock FT_Match_Size host seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_request_metrics(_: *mut FtFace, _: *const FtSizeRequest) {
    panic!("install stock FT_Request_Metrics host seam")
}
/// Host substitutes for verified, unported stock callees; install before use.
#[cfg(not(target_os = "none"))]
pub static mut FT_MATCH_SIZE: MatchSize = missing_match_size;
#[cfg(not(target_os = "none"))]
pub static mut FT_REQUEST_METRICS: RequestMetrics = missing_request_metrics;
/// Host substitute for the signed trace level at 0x08b209f8.
#[cfg(not(target_os = "none"))]
pub static mut FT_REQUEST_TRACE_LEVEL: i32 = 0;

/// `FT_Request_Size` — FUN_0804e980 at 0x0804e980, true size 244 bytes,
/// [0x0804e980,0x0804ea74), including the literal and trace string pool.
/// Executable body is 196 bytes. Raw aligned ARM decoding verifies two
/// plain incoming BLs, no predicated incoming BLs, three plain outgoing
/// BLs, one predicated outgoing BLGE, and one indirect BLX callback.
///
/// Reject a null face (0x23), null request, negative dimensions or kind >=5
/// (6). Prefer the driver's request_size callback. Otherwise a non-scalable
/// fixed-size face matches a bitmap strike with ignore_width=0, propagates
/// match failure, traces success at signed level >=3 and selects the strike.
/// All other faces request metrics and return zero. The callback receives
/// face->size and the original request; Ghidra's extra arguments are spurious.
///
/// Deviations: use the existing ft_error_trace sink contract (unused variadic
/// slots zeroed); host builds substitute the two unported stock callees and
/// trace level. Target metric/match algorithms remain stock, not emulated.
///
/// # Safety
/// Non-null request must be readable. A validated face must contain valid
/// driver/class and size records satisfying the selected callback or stock
/// callee contracts. Host seams must be installed without concurrent use.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_request_size(face: *mut FtFace, request: *const FtSizeRequest) -> i32 {
    if face.is_null() { return 0x23; }
    if request.is_null() || (*request).width < 0 || (*request).height < 0 || (*request).kind >= 5 {
        return 6;
    }
    let driver = (*face).driver.cast::<FtDriver>();
    let class = (*driver).clazz.cast::<FtRequestDriverClass>();
    if let Some(request_size) = (*class).request_size {
        return request_size((*face).size.cast(), request);
    }
    if (*face).face_flags & 3 == 2 {
        #[cfg(target_os = "none")]
        let match_size: MatchSize = core::mem::transmute(0x0804_cf38usize);
        #[cfg(not(target_os = "none"))]
        let match_size = FT_MATCH_SIZE;
        let mut strike_index = 0;
        let error = match_size(face, request, 0, &mut strike_index);
        if error != 0 { return error; }
        #[cfg(target_os = "none")]
        let trace_level = (0x08b2_09f8usize as *const i32).read_volatile();
        #[cfg(not(target_os = "none"))]
        let trace_level = FT_REQUEST_TRACE_LEVEL;
        if trace_level >= 3 {
            crate::ft::trace::ft_error_trace(
                b"FT_Request_Size: bitmap strike %lu matched\n\0".as_ptr(), strike_index as u32, 0, 0,
            );
        }
        return ft_select_size(face, strike_index);
    }
    #[cfg(target_os = "none")]
    let request_metrics: RequestMetrics = core::mem::transmute(0x0804_e750usize);
    #[cfg(not(target_os = "none"))]
    let request_metrics = FT_REQUEST_METRICS;
    request_metrics(face, request);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(kind: u8, width: i32, height: i32) -> FtSizeRequest {
        FtSizeRequest { kind, width, height, horizontal_resolution: 0, vertical_resolution: 0 }
    }

    #[test]
    fn invalid_handles_and_request_boundaries_precede_driver_access() {
        unsafe {
            assert_eq!(ft_request_size(core::ptr::null_mut(), core::ptr::null()), 0x23);
            let mut face: FtFace = core::mem::zeroed();
            assert_eq!(ft_request_size(&mut face, core::ptr::null()), 6);
            for (kind, width, height) in [(0, -1, 0), (4, 0, i32::MIN), (5, 0, 0), (255, i32::MAX, i32::MAX)] {
                assert_eq!(ft_request_size(&mut face, &request(kind, width, height)), 6);
            }
        }
    }

    unsafe extern "C" fn driver_request(size: *mut FtSizeRec, request: *const FtSizeRequest) -> i32 {
        (*size).metrics.height = (*request).height;
        (*size).metrics.max_advance = (*request).width;
        (*size).metrics.x_ppem = (*request).kind as u16;
        -73
    }

    #[test]
    fn driver_override_accepts_all_valid_kinds_even_for_bitmap_faces() {
        unsafe {
            let mut class: FtRequestDriverClass = core::mem::zeroed();
            class.request_size = Some(driver_request);
            let mut driver: FtDriver = core::mem::zeroed();
            driver.clazz = &class.prefix;
            let mut size: FtSizeRec = core::mem::zeroed();
            let mut face: FtFace = core::mem::zeroed();
            face.face_flags = 2;
            face.driver = (&mut driver as *mut FtDriver).cast();
            face.size = (&mut size as *mut FtSizeRec).cast();
            for kind in 0..5 {
                assert_eq!(ft_request_size(&mut face, &request(kind, 0, i32::MAX)), -73);
                assert_eq!((size.metrics.height, size.metrics.max_advance, size.metrics.x_ppem), (i32::MAX, 0, kind as u16));
            }
        }
    }
}
