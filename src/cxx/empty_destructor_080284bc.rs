//! Empty cleanup destructor — `FUN_080284bc` @ 0x080284bc (4 bytes).
//!
//! True extent [0x080284bc, 0x080284c0): raw word 0xe12fff1e (`bx lr`).
//! The next word is an independent return body, not a veneer target.
//! Full-image aligned A32 decoding verifies two plain inbound BLs at
//! 0x082ea24c and 0x082ea424, zero predicated BLs, and zero outbound calls.
//! No aligned DATA references target this entry. Both cleanup paths pass
//! the saved object from sp+0x48; neither consumes the returned r0.
//! Concrete owner type is unrecovered. Algorithm: preserve the incoming
//! object address without reading, writing, or freeing storage. Preserve
//! r0 despite Ghidra's void prototype. Deliberate behavioral deviations:
//! none. A dedicated text section prevents folding with other empty
//! destructors; LLVM may emit a balanced frame instead of a bare return.

use core::ffi::c_void;

/// Accepts NULL, unaligned, and dangling addresses without dereferencing.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_080284bc")]
#[inline(never)]
pub unsafe extern "C" fn empty_destructor_080284bc(object: *mut c_void) -> *mut c_void {
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_null_unaligned_dangling_and_native_width_addresses() {
        for address in [0usize, 1, 3, 0x0800_0001, 0xffff_ffff, usize::MAX] {
            let object = address as *mut c_void;
            assert_eq!(unsafe { empty_destructor_080284bc(object) }, object);
        }
    }

    #[test]
    fn preserves_object_and_adjacent_storage() {
        let mut storage = [0xa5u8; 33];
        storage[1] = 0x37;
        let before = storage;
        let object = unsafe { storage.as_mut_ptr().add(1) }.cast();
        assert_eq!(unsafe { empty_destructor_080284bc(object) }, object);
        assert_eq!(storage, before);
    }
}
