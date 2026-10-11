//! Guarded size of the object's 24-byte-record collection.
//!
//! FUN_08053f38 @ 0x08053f38: true extent 0x08053f38..0x08053f70,
//! 56 bytes (52 code + 4 literal). Raw A32 census: two inbound plain BLs
//! (0x08054040, 0x08111570), zero predicated BLs; one outbound plain BL,
//! zero predicated BLs, and one conditional tail B to vector_size_elem24.
//! Dispatch selector 0x80000000, secondary selector zero, callback literal
//! 0x080bf474. A nonzero dispatch status returns zero without reading bounds;
//! success returns the signed, truncating count of the vector at +0xeb0.
//!
//! Deviations: discard dead incoming r1 (the dispatcher saves but never uses
//! it), passing zero instead. Read target bounds as two u32 words on every
//! platform, then reuse the canonical vector_size_elem24 port with native
//! pointers. Host callers supply the unported dispatcher; no guessed identity.

use crate::cxx::templates::{VectorBounds, vector_size_elem24};

#[cfg(not(target_os = "none"))]
pub type CollectionDispatch = unsafe extern "C" fn(*mut u8, u32, u32, u32, usize) -> i32;

/// # Safety
/// Object must satisfy retail dispatcher 0x0808cec4's contract and, on
/// success, contain readable aligned u32 bounds at +0xeb0 and +0xeb4.
/// Dispatch may update those bounds; they are read only after it returns.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_collection_size(
    object: *mut u8,
    #[cfg(not(target_os = "none"))] dispatch: CollectionDispatch,
) -> i32 {
    #[cfg(target_os = "none")]
    let dispatch: unsafe extern "C" fn(*mut u8, u32, u32, u32, usize) -> i32 =
        core::mem::transmute(0x0808_cec4usize);
    if dispatch(object, 0, 0x8000_0000, 0, 0x080b_f474) != 0 {
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

    unsafe extern "C" fn fail(_: *mut u8, _: u32, _: u32, _: u32, _: usize) -> i32 { -50 }
    unsafe extern "C" fn ready(_: *mut u8, _: u32, _: u32, _: u32, _: usize) -> i32 { 0 }
    unsafe extern "C" fn populate(object: *mut u8, _: u32, _: u32, _: u32, _: usize) -> i32 {
        let bounds = object.add(0xeb0).cast::<u32>();
        bounds.write(0x1000);
        bounds.add(1).write(0x1049);
        0
    }

    #[test]
    fn dispatch_failure_does_not_access_bounds() {
        assert_eq!(unsafe { object_collection_size(core::ptr::null_mut(), fail) }, 0);
    }

    #[test]
    fn signed_partial_and_wrapping_spans() {
        let mut object = [0u32; 0xeb8 / 4];
        for (begin, end, expected) in [
            (0, 0, 0), (0x1000, 0x1017, 0), (0x1000, 0x1018, 1),
            (0x1000, 0x1047, 2), (0x1019, 0x1000, -1),
            (0xffff_fff0, 0x20, 2), (0, 0x8000_0000, -89_478_485),
        ] {
            object[0xeb0 / 4] = begin;
            object[0xeb4 / 4] = end;
            assert_eq!(unsafe { object_collection_size(object.as_mut_ptr().cast(), ready) }, expected);
        }
    }

    #[test]
    fn count_uses_bounds_populated_by_dispatch() {
        let mut object = [0u32; 0xeb8 / 4];
        assert_eq!(unsafe { object_collection_size(object.as_mut_ptr().cast(), populate) }, 3);
    }
}
