//! `opaque_object_implementation` — original: `FUN_08104050` @ `0x08104050`
//! (8 bytes, `0x08104050..0x08104057`; the next real function begins at
//! `0x08104058`).
//!
//! Full-image A32 decoding finds three inbound unconditional plain `bl` calls
//! (`0x08235848`, `0x08235990`, and `0x08235a90`) and zero predicated `bl`
//! calls. The function contains no calls.
//!
//! # Algorithm
//!
//! Load and return the opaque object's implementation pointer stored at target
//! byte offset `+0xe8`. The raw `ldr r0, [r0, #0xe8]; bx lr` sequence has no
//! NULL guard. Deliberate deviation: the Rust signature expresses the loaded
//! word as `*mut u8`; the retailOS word's concrete implementation type remains
//! unrecovered.

const IMPLEMENTATION_OFFSET: usize = 0xe8;

/// opaque_object_implementation — original: `FUN_08104050` @ `0x08104050`
/// (8 bytes; three unconditional direct `bl` call sites).
///
/// # Safety
///
/// `object` must be non-NULL and readable through its target-layout pointer
/// field at byte offset `+0xe8`. RetailOS does not validate it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_object_implementation(object: *const u8) -> *mut u8 {
    core::ptr::read(object.add(IMPLEMENTATION_OFFSET).cast::<*mut u8>())
}

#[cfg(test)]
mod tests {
    use super::opaque_object_implementation;

    #[repr(C)]
    struct OpaqueObject {
        padding: [u8; 0xe8],
        implementation: *mut u8,
    }

    #[test]
    fn returns_the_implementation_pointer_at_target_offset_e8() {
        let expected = 0x1234_5000usize as *mut u8;
        let object = OpaqueObject {
            padding: [0; 0xe8],
            implementation: expected,
        };
        assert_eq!(unsafe { opaque_object_implementation((&object as *const OpaqueObject).cast()) }, expected);
    }

    #[test]
    fn returns_a_null_implementation_pointer() {
        let object = OpaqueObject {
            padding: [0xff; 0xe8],
            implementation: core::ptr::null_mut(),
        };
        assert!(unsafe { opaque_object_implementation((&object as *const OpaqueObject).cast()) }.is_null());
    }
}
