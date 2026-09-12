//! `object_offset_48` — original: `FUN_0829a06c` @ `0x0829a06c` (8 bytes).
//!
//! Raw `osos.dec` has exactly `add r0,r0,#0x48; bx lr`; the following function
//! starts at `0x0829a074`, confirming Ghidra's eight-byte extent. Decoding every
//! aligned ARM B/BL immediate in the image finds eight direct, unconditional
//! `bl` callers (`0x080ac9ec`, `0x08109300`, `0x08109534`, `0x0810a48c`,
//! `0x08128130`, `0x0817544c`, `0x081dd9c8`, and `0x081e92a0`) and no predicated
//! calls or data-word references. Each caller obtains the object from
//! `task_ctx_field_0x30`, downcasts it to class id `0x80`, then uses this result
//! as the base of an opaque payload. No recovered evidence establishes a more
//! specific type or payload layout, so the port retains the offset-based name.
//!
//! # Algorithm
//!
//! Return `object + 0x48` without reading, writing, or NULL-guarding `object`.
//! `wrapping_add` preserves the raw ARM address-addition behavior, including
//! `NULL -> 0x48` and target-width wraparound.
//!
//! # Deliberate deviations
//!
//! None.

/// Returns the address 0x48 bytes after an opaque application's object base.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.object_offset_48")]
pub extern "C" fn object_offset_48(object: *mut u8) -> *mut u8 {
    object.wrapping_add(0x48)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFSET: usize = 0x48;
    const GUARD: u8 = 0xa5;

    #[test]
    fn returns_the_exact_interior_address_without_touching_storage() {
        let mut object = [GUARD; OFFSET + 2];
        object[OFFSET - 1] = 0x3c;
        object[OFFSET] = 0x6d;
        object[OFFSET + 1] = 0xc3;
        let before = object;

        let result = object_offset_48(object.as_mut_ptr());

        assert_eq!(result, unsafe { object.as_mut_ptr().add(OFFSET) });
        assert_eq!(object, before, "address calculation must not mutate the object");
    }

    #[test]
    fn maps_null_to_the_raw_offset_address() {
        assert_eq!(object_offset_48(core::ptr::null_mut()) as usize, OFFSET);
    }
}
