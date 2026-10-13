//! Empty cleanup destructor — `FUN_080284c4` @ 0x080284c4 (4 bytes).
//!
//! Raw extent [0x080284c4, 0x080284c8) is 0xe12fff1e (`bx lr`),
//! followed by another independent return body. This is not a veneer.
//! Full-image aligned A32 decoding verifies two inbound plain BLs at
//! 0x082ea254 and 0x082ea434, zero predicated BLs, and zero outbound calls.
//! No aligned DATA references target this entry. Both cleanup paths load
//! the saved object from sp+0x4c, then overwrite r0 with the next object.
//! Concrete type unrecovered; retain r0 passthrough despite Ghidra's void
//! prototype. Algorithm: return the incoming address without memory access.
//! Deliberate behavioral deviations: none. A dedicated text section avoids
//! folding with other empty destructors; LLVM may add a balanced frame.

use core::ffi::c_void;

/// Accepts NULL, unaligned, and dangling addresses without dereferencing.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_080284c4")]
#[inline(never)]
pub unsafe extern "C" fn empty_destructor_080284c4(object: *mut c_void) -> *mut c_void {
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_null_unaligned_dangling_and_native_width_addresses() {
        for address in [0usize, 1, 3, 0x0800_0001, 0xffff_ffff, usize::MAX] {
            let object = address as *mut c_void;
            assert_eq!(unsafe { empty_destructor_080284c4(object) }, object);
        }
    }

    #[test]
    fn preserves_object_and_adjacent_storage() {
        let mut storage = [0xa5u8; 33];
        storage[1] = 0x37;
        let before = storage;
        let object = unsafe { storage.as_mut_ptr().add(1) }.cast();
        assert_eq!(unsafe { empty_destructor_080284c4(object) }, object);
        assert_eq!(storage, before);
    }
}
