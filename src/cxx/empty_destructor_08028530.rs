//! Empty cleanup destructor — `FUN_08028530` @ 0x08028530 (4 bytes).
//!
//! Raw extent [0x08028530, 0x08028534) is the single word 0xe12fff1e,
//! `bx lr`; the next separately called cleanup entry begins at 0x08028534.
//! Full-image aligned ARM branch decoding finds two inbound plain BLs at
//! 0x082ea28c and 0x082ea474, zero predicated BLs, zero tail branches,
//! and zero outbound calls. No aligned data word references this entry.
//! Both callers pass a saved object during cleanup; its concrete type is
//! unrecovered. This is not a branch or literal-load veneer.
//!
//! Algorithm: access no memory and return the incoming object address in r0.
//! Deliberate deviations: none. A dedicated section prevents LLVM folding
//! this entry into another identical empty destructor.

use core::ffi::c_void;

/// Leaves even NULL, dangling, or unaligned object addresses untouched.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_08028530")]
#[inline(never)]
pub unsafe extern "C" fn empty_destructor_08028530(object: *mut c_void) -> *mut c_void {
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_null_unaligned_and_dangling_addresses() {
        for address in [0usize, 1, 0x0800_0001, 0xffff_ffff, usize::MAX] {
            let object = address as *mut c_void;
            assert_eq!(unsafe { empty_destructor_08028530(object) }, object);
        }
    }

    #[test]
    fn leaves_live_object_and_surrounding_bytes_unchanged() {
        let mut storage = [0xa5u8; 33];
        let before = storage;
        let object = unsafe { storage.as_mut_ptr().add(1) }.cast();
        assert_eq!(unsafe { empty_destructor_08028530(object) }, object);
        assert_eq!(storage, before);
    }
}
