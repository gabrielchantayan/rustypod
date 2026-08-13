//! Fixed-width byte identity-table initialization.
//!
//! `initialize_byte_identity_slot` — original: `FUN_0802b9ec` @
//! `0x0802b9ec` (24 bytes). Reference:
//! `/home/gabe/Programming/ipod-decomp/decomp/c/001/0802b9ec_FUN_0802b9ec.c`;
//! raw ARM is `0x0802b9ec..0x0802ba04`.
//!
//! The ARM routine takes a destination in r0 and writes the byte value `i` to
//! `slot + i` for every `i` from 0 through 255. It has no length argument or
//! return value, so every call initializes exactly one 256-byte identity slot.

/// Bytes initialized by [`initialize_byte_identity_slot`].
pub const BYTE_IDENTITY_SLOT_BYTES: usize = 0x100;

/// initialize_byte_identity_slot — original: `FUN_0802b9ec` @ `0x0802b9ec`
/// (24 bytes).
///
/// Initializes exactly one 256-byte byte-identity slot: `slot[i] = i as u8`
/// for each `i` in `0..256`.
///
/// # Safety
///
/// `slot` must designate 256 writable, contiguous bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn initialize_byte_identity_slot(slot: *mut u8) {
    for byte in 0..=u8::MAX {
        slot.add(byte as usize).write_volatile(byte);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn initializes_the_complete_identity_mapping_and_only_its_slot() {
        let mut bytes = [0xa5u8; BYTE_IDENTITY_SLOT_BYTES + 2];
        let slot = unsafe { bytes.as_mut_ptr().add(1) };

        unsafe { initialize_byte_identity_slot(slot) };

        assert_eq!(bytes[0], 0xa5, "byte before the slot");
        assert_eq!(bytes[1], 0, "first identity entry");
        assert_eq!(bytes[BYTE_IDENTITY_SLOT_BYTES], u8::MAX, "last identity entry");
        assert_eq!(bytes[BYTE_IDENTITY_SLOT_BYTES + 1], 0xa5, "byte after the slot");
        for (index, &value) in bytes[1..=BYTE_IDENTITY_SLOT_BYTES].iter().enumerate() {
            assert_eq!(value, index as u8, "identity entry {index}");
        }
    }
}
