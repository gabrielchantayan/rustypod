//! `opaque_vtable_payload_construct` — retailOS `FUN_0816f11c` @
//! `0x0816f11c`.
//!
//! Raw ARM establishes a 12-byte instruction body followed by the vtable
//! literal `0x08988ad8` at `0x0816f12c`; `0x0816f130` begins the next real
//! function, for a true 16-byte extent. A whole-image aligned A32 decode finds
//! three inbound plain `bl` sites (`0x081356d4`, `0x08173760`, and
//! `0x081c934c`) and no predicated inbound `bl` sites. There are no outgoing
//! calls.
//!
//! The constructor first stores its opaque payload at +4, then installs the
//! literal vtable at +0, retaining `this` in r0. The vtable has no recovered
//! semantic identity and is therefore represented only as its stored address.
//! Deliberate deviation: volatile stores preserve the observed store order;
//! LLVM may add a standard frame/prologue.

/// Vtable literal loaded from `0x0816f12c`.
pub const OPAQUE_VTABLE_PAYLOAD_VTABLE_ADDRESS: u32 = 0x0898_8ad8;

/// Initializes the two-word opaque vtable/payload object and returns `this`.
///
/// # Safety
///
/// `this` must be valid for aligned, writable u32 stores at +0 and +4. The
/// retail constructor performs no null or alignment checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_vtable_payload_construct")]
#[inline(never)]
pub unsafe extern "C" fn opaque_vtable_payload_construct(this: *mut u8, payload: u32) -> *mut u8 {
    unsafe {
        this.add(4).cast::<u32>().write_volatile(payload);
        this.cast::<u32>().write_volatile(OPAQUE_VTABLE_PAYLOAD_VTABLE_ADDRESS);
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_words_in_its_eight_byte_extent() {
        let mut storage = [0xa5_u8; 16];
        let this = unsafe { storage.as_mut_ptr().add(4) };

        let returned = unsafe { opaque_vtable_payload_construct(this, 0x1357_9bdf) };

        assert_eq!(returned, this);
        assert_eq!(u32::from_le_bytes(storage[4..8].try_into().unwrap()), OPAQUE_VTABLE_PAYLOAD_VTABLE_ADDRESS);
        assert_eq!(u32::from_le_bytes(storage[8..12].try_into().unwrap()), 0x1357_9bdf);
        assert_eq!(&storage[..4], &[0xa5; 4]);
        assert_eq!(&storage[12..], &[0xa5; 4]);
    }

    #[test]
    fn preserves_all_payload_bits() {
        let mut storage = [0_u8; 8];

        unsafe { opaque_vtable_payload_construct(storage.as_mut_ptr(), u32::MAX) };

        assert_eq!(u32::from_le_bytes(storage[4..8].try_into().unwrap()), u32::MAX);
    }
}
