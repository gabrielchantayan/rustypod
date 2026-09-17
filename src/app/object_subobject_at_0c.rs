//! object_subobject_at_0c — original: `FUN_082a1ffc` @ `0x082a1ffc` (8 bytes).
//!
//! Raw ARM is `add r0, r0, #0xc; bx lr`. The next distinct function begins at
//! `0x082a2004` with `push {r4, lr}`. There are four incoming plain BL calls
//! (0x081177f4, 0x081181dc, 0x0828a5a8, 0x0828b9dc) and no predicated BL
//! calls. Each caller uses the result as the object embedded at byte +0x0c;
//! its concrete type is not established.
//!
//! # Algorithm
//!
//! Return the supplied opaque-object address advanced by 12 bytes. The
//! original neither reads memory nor validates the address.
//!
//! LLVM adds a standard frame prologue and epilogue around the equivalent add;
//! match.py confirms the only body instruction remains `add r0, r0, #12`.
//! Deliberate deviation: `wrapping_add` expresses the original unchecked ARM
//! address arithmetic without adding Rust allocation or dereference preconditions.

/// Byte offset of the embedded opaque subobject.
const SUBOBJECT: usize = 0x0c;

/// Returns the opaque subobject located at byte +0x0c.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn object_subobject_at_0c(object: *mut u8) -> *mut u8 {
    object.wrapping_add(SUBOBJECT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advances_each_byte_alignment_by_exactly_twelve_bytes() {
        let mut storage = [0u8; SUBOBJECT + 4];
        for alignment in 0..4 {
            let object = unsafe { storage.as_mut_ptr().add(alignment) };
            assert_eq!(object_subobject_at_0c(object), unsafe { object.add(SUBOBJECT) });
        }
    }

    #[test]
    fn does_not_access_the_opaque_object() {
        let object = core::ptr::null_mut();
        assert_eq!(object_subobject_at_0c(object) as usize, SUBOBJECT);
    }
}
