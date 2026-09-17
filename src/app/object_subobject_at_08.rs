//! object_subobject_at_08 — original: `FUN_082a1dec` @ `0x082a1dec` (8 bytes).
//!
//! Raw ARM is `add r0, r0, #8; bx lr`. The next distinct function begins at
//! `0x082a1df4` with `bx lr`. There are four incoming plain BL calls
//! (0x08100338, 0x0810034c, 0x08297788, and 0x0829779c) and no predicated BL
//! calls. Each caller uses the result as an opaque object subobject at byte
//! +0x08; its concrete type is not established.
//!
//! # Algorithm
//!
//! Return the supplied opaque-object address advanced by eight bytes. The
//! original neither reads memory nor validates the address.
//!
//! LLVM may add a standard frame prologue and epilogue around the equivalent
//! add. Deliberate deviation: `wrapping_add` expresses the original unchecked
//! ARM address arithmetic without adding Rust allocation or dereference
//! preconditions.

/// Byte offset of the embedded opaque subobject.
const SUBOBJECT: usize = 0x08;

/// Returns the opaque subobject located at byte +0x08.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn object_subobject_at_08(object: *mut u8) -> *mut u8 {
    object.wrapping_add(SUBOBJECT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advances_each_byte_alignment_by_exactly_eight_bytes() {
        let mut storage = [0u8; SUBOBJECT + 4];
        for alignment in 0..4 {
            let object = unsafe { storage.as_mut_ptr().add(alignment) };
            assert_eq!(object_subobject_at_08(object), unsafe { object.add(SUBOBJECT) });
        }
    }

    #[test]
    fn does_not_access_the_opaque_object() {
        let object = core::ptr::null_mut();
        assert_eq!(object_subobject_at_08(object) as usize, SUBOBJECT);
    }
}
