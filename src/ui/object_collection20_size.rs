//! Guarded size of the object's 20-byte-record collection.
//!
//! FUN_08053ea0 @ 0x08053ea0: true extent 0x08053ea0..0x08053edc,
//! 60 bytes (56 code + 4 literal), next real entry 0x08053edc.
//! Raw A32 census: two inbound plain BLs (0x08111538, 0x0813e540),
//! zero predicated inbound BLs; one outbound plain BL, zero predicated
//! outbound BLs, and one conditional tail B to vector_size_elem20.
//! Dispatch selector 4, secondary selector zero, callback literal 0x080c6b4c.
//! Nonzero dispatch status returns zero without reading bounds; success
//! returns the signed, truncating count of the vector at +0xe64.
//!
//! Deviations: discard dead incoming r1 (saved but unused by the dispatcher),
//! passing zero. Read target bounds as aligned u32 words on every platform,
//! then reuse vector_size_elem20 with native pointers. Host callers inject
//! the unported dispatcher using the existing CollectionDispatch convention.

use crate::cxx::templates::{VectorBounds, vector_size_elem20};
#[cfg(not(target_os = "none"))]
use super::object_collection_size::CollectionDispatch;

/// # Safety
/// Object must satisfy retail dispatcher 0x0808cec4's contract and contain
/// readable aligned u32 bounds at +0xe64/+0xe68 after successful dispatch.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_collection20_size(
    object: *mut u8,
    #[cfg(not(target_os = "none"))] dispatch: CollectionDispatch,
) -> i32 {
    #[cfg(target_os = "none")]
    let dispatch: unsafe extern "C" fn(*mut u8, u32, u32, u32, usize) -> i32 =
        core::mem::transmute(0x0808_cec4usize);
    if dispatch(object, 0, 4, 0, 0x080c_6b4c) != 0 {
        return 0;
    }
    let bounds = object.add(0xe64).cast::<u32>();
    let vector = VectorBounds {
        begin: bounds.read() as usize as *mut u8,
        end: bounds.add(1).read() as usize as *mut u8,
    };
    vector_size_elem20(&vector)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn fail(_: *mut u8, _: u32, _: u32, _: u32, _: usize) -> i32 { -50 }
    unsafe extern "C" fn ready(_: *mut u8, _: u32, _: u32, _: u32, _: usize) -> i32 { 0 }
    unsafe extern "C" fn populate(object: *mut u8, _: u32, _: u32, _: u32, _: usize) -> i32 {
        let bounds = object.add(0xe64).cast::<u32>();
        bounds.write(0x1000);
        bounds.add(1).write(0x104f);
        0
    }

    #[test]
    fn failure_skips_bounds() {
        assert_eq!(unsafe { object_collection20_size(core::ptr::null_mut(), fail) }, 0);
    }

    #[test]
    fn signed_partial_and_wrapping_spans() {
        let mut object = [0u32; 0xe6c / 4];
        for (begin, end, expected) in [
            (0, 0, 0), (0x1000, 0x1013, 0), (0x1000, 0x1014, 1),
            (0x1000, 0x103b, 2), (0x1013, 0x1000, 0),
            (0x1015, 0x1000, -1), (0xffff_fff0, 0x20, 2),
            (0, 0x8000_0000, -107_374_182), (0, 0x7fff_ffff, 107_374_182),
        ] {
            object[0xe64 / 4] = begin;
            object[0xe68 / 4] = end;
            assert_eq!(unsafe { object_collection20_size(object.as_mut_ptr().cast(), ready) }, expected);
        }
    }

    #[test]
    fn reads_bounds_after_dispatch() {
        let mut object = [0u32; 0xe6c / 4];
        object[0xe64 / 4] = 0x2000;
        object[0xe68 / 4] = 0x2000;
        assert_eq!(unsafe { object_collection20_size(object.as_mut_ptr().cast(), populate) }, 3);
    }
}
