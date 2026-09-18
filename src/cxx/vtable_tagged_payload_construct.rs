//! `vtable_tagged_payload_construct` — retailOS `FUN_081fc9c0` @
//! `0x081fc9c0`.
//!
//! Raw ARM is exactly 20 bytes (five words), ending with `bx lr` at
//! `0x081fc9d0`; the following word at `0x081fc9d4` is the vtable literal
//! `0x08990e5c`, and the next real function begins at `0x081fc9d8`.
//! Decoding direct calls in `osos.dec` finds four inbound `bl` instructions
//! (`0x081fc9f0`, `0x08207698`, `0x082076c4`, and `0x0820b8dc`), all plain
//! unconditional forms and no predicated `bl` forms.
//!
//! The constructor stores its shared vtable at +0, its one-byte type tag at
//! +4, and its payload word at +8, then returns `this` unchanged in `r0`.
//! Callers replace the vtable for their derived object after this prefix is
//! initialized. Deliberate deviation: volatile stores preserve the observed
//! store order; LLVM still adds a standard frame/prologue around the same body.

/// Vtable literal loaded from `0x081fc9d4`.
pub const TAGGED_PAYLOAD_VTABLE_ADDRESS: u32 = 0x0899_0e5c;

/// Constructs the common vtable-tagged payload prefix and returns `this`.
///
/// # Safety
///
/// `this` must be valid for a byte store at +4 and aligned, writable word
/// stores at +0 and +8. The retail constructor performs no null or alignment
/// checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vtable_tagged_payload_construct")]
#[inline(never)]
pub unsafe extern "C" fn vtable_tagged_payload_construct(
    this: *mut u8,
    type_tag: u8,
    payload: u32,
) -> *mut u8 {
    unsafe {
        this.add(4).write_volatile(type_tag);
        this.cast::<u32>().write_volatile(TAGGED_PAYLOAD_VTABLE_ADDRESS);
        this.add(8).cast::<u32>().write_volatile(payload);
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_prefix_without_touching_adjacent_bytes() {
        let mut object = [0xa5_u8; 16];
        let this = object.as_mut_ptr();

        let returned = unsafe { vtable_tagged_payload_construct(this, 3, 0x1234_5678) };

        assert_eq!(returned, this);
        assert_eq!(u32::from_le_bytes(object[0..4].try_into().unwrap()), TAGGED_PAYLOAD_VTABLE_ADDRESS);
        assert_eq!(object[4], 3);
        assert_eq!(&object[5..8], &[0xa5; 3]);
        assert_eq!(u32::from_le_bytes(object[8..12].try_into().unwrap()), 0x1234_5678);
        assert_eq!(&object[12..], &[0xa5; 4]);
    }

    #[test]
    fn accepts_each_observed_type_tag_value() {
        for type_tag in 0_u8..=3 {
            let mut object = [0_u8; 12];
            unsafe { vtable_tagged_payload_construct(object.as_mut_ptr(), type_tag, type_tag as u32) };
            assert_eq!(object[4], type_tag);
            assert_eq!(u32::from_le_bytes(object[8..12].try_into().unwrap()), type_tag as u32);
        }
    }
}
