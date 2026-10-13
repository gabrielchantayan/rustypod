//! `object_no_op_080276b8` — retailOS `FUN_080276b8` @ 0x080276b8.
//!
//! True extent: 4 bytes, 0x080276b8..0x080276bc. Raw firmware contains
//! `0xe12fff1e` (`bx lr`); the next independently callable return stub begins
//! at 0x080276bc. This is neither a branch veneer nor a literal-load veneer.
//! Complete-image ARM immediate-BL decoding finds two plain unconditional
//! callers (0x082f8df4, 0x08332b84), zero predicated BL callers, and no outgoing
//! calls. No aligned DATA word references this entry. Both callers load an
//! object address from a stack slot into r0; its concrete class and whether
//! this is a destructor are unestablished.
//!
//! Algorithm: access no memory and return the incoming object pointer unchanged,
//! preserving the raw instruction's r0 behavior despite Ghidra's void signature.
//! Deliberate behavioral deviations: none. LLVM adds a frame-pointer prologue
//! and epilogue (push, mov, pop), preserving r0 and restoring sp on return.
//! A dedicated text section prevents folding into another identical return stub.

use core::ffi::c_void;

/// Preserve the object address without accessing or releasing the object.
///
/// NULL, unaligned, and dangling addresses are accepted: nothing is dereferenced.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.object_no_op_080276b8")]
#[inline(never)]
pub unsafe extern "C" fn object_no_op_080276b8(object: *mut c_void) -> *mut c_void {
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_null_unaligned_and_unmapped_addresses() {
        for address in [0usize, 1, 0x0800_0001, 0x0802_76b8, usize::MAX] {
            let object = address as *mut c_void;
            assert_eq!(unsafe { object_no_op_080276b8(object) }, object);
        }
    }

    #[test]
    fn leaves_every_byte_of_a_live_object_unchanged() {
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() { *byte = (index as u8) ^ 0xa5; }
        let before = bytes;
        let object = bytes.as_mut_ptr().cast::<c_void>();
        assert_eq!(unsafe { object_no_op_080276b8(object) }, object);
        assert_eq!(bytes, before);
    }
}
