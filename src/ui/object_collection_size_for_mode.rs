//! Mode-selected size of the object's 24-byte-record collection.
//!
//! FUN_08053e50 @ 0x08053e50: true extent [0x08053e50,0x08053ea0),
//! 80 bytes (76 code + 4 literal). Raw A32 census: two inbound plain BLs
//! at 0x08111544 and 0x0813e548, zero predicated BLs; one outbound plain
//! BL, zero predicated BLs. Nonzero byte +0xef9 tail-branches to
//! object_collection_size. Otherwise dispatch selector 2, secondary zero,
//! callback 0x080bf474; failure returns zero, success counts the vector at
//! +0xeb0 using signed wrapping span / 24, truncating toward zero.
//! Deviations: dead incoming r1 is replaced by zero, as in the canonical
//! collection-size port. Host dispatcher injection and native temporary
//! bounds follow that port. Tail branches become ordinary Rust calls.

use crate::cxx::templates::{VectorBounds, vector_size_elem24};
use super::object_collection_size::object_collection_size;
#[cfg(not(target_os = "none"))]
use super::object_collection_size::CollectionDispatch;
/// # Safety
/// Object must be readable through +0xef9 and satisfy the retail dispatcher's
/// contract. Successful dispatch must leave aligned u32 bounds at +0xeb0/+0xeb4.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_collection_size_for_mode(
    object: *mut u8,
    #[cfg(not(target_os = "none"))] dispatch: CollectionDispatch,
) -> i32 {
    if object.add(0xef9).read() != 0 {
        return object_collection_size(object, #[cfg(not(target_os = "none"))] dispatch);
    }
    #[cfg(target_os = "none")]
    let dispatch: unsafe extern "C" fn(*mut u8, u32, u32, u32, usize) -> i32 =
        core::mem::transmute(0x0808_cec4usize);
    if dispatch(object, 0, 2, 0, 0x080b_f474) != 0 {
        return 0;
    }
    let bounds = object.add(0xeb0).cast::<u32>();
    let vector = VectorBounds {
        begin: bounds.read() as usize as *mut u8,
        end: bounds.add(1).read() as usize as *mut u8,
    };
    vector_size_elem24(&vector)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn populate(object: *mut u8, _: u32, selector: u32, _: u32, _: usize) -> i32 {
        // Different collections expose different spans; dispatch replaces stale bounds.
        let bounds = object.add(0xeb0).cast::<u32>();
        bounds.write(0xffff_fff0);
        bounds.add(1).write(if selector == 2 { 0x39 } else { 0x20 });
        0
    }
    unsafe extern "C" fn fail(_: *mut u8, _: u32, _: u32, _: u32, _: usize) -> i32 { -50 }
    unsafe extern "C" fn ready(_: *mut u8, _: u32, _: u32, _: u32, _: usize) -> i32 { 0 }

    #[test]
    fn mode_selects_collection_and_reads_post_dispatch_bounds() {
        let mut object = [0u32; 0xf00 / 4];
        for (mode, expected) in [(0, 3), (1, 2), (255, 2)] {
            unsafe {
                object.as_mut_ptr().cast::<u8>().add(0xef9).write(mode);
                assert_eq!(object_collection_size_for_mode(object.as_mut_ptr().cast(), populate), expected);
            }
        }
    }

    #[test]
    fn failure_empty_partial_reversed_and_signed_extreme_spans() {
        let mut object = [0u32; 0xf00 / 4];
        for mode in [0, 1] {
            unsafe { object.as_mut_ptr().cast::<u8>().add(0xef9).write(mode); }
            object[0xeb0 / 4] = 0;
            object[0xeb4 / 4] = 0x8000_0000;
            assert_eq!(unsafe { object_collection_size_for_mode(object.as_mut_ptr().cast(), fail) }, 0);
            for (begin, end, expected) in [
                (0, 0, 0), (0x1000, 0x1017, 0), (0x1000, 0x1018, 1),
                (0x1019, 0x1000, -1), (0xffff_fff0, 0x20, 2),
                (0, 0x8000_0000, -89_478_485),
            ] {
                object[0xeb0 / 4] = begin;
                object[0xeb4 / 4] = end;
                assert_eq!(unsafe { object_collection_size_for_mode(object.as_mut_ptr().cast(), ready) }, expected);
            }
        }
    }
}
