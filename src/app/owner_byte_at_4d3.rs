//! Read the owner's raw unsigned byte at +0x4d3.
//!
//! Original `FUN_08116410` @ **0x08116410**, true size **8 bytes**:
//! `e5d004d3` (ldrb r0,[r0,#0x4d3]), `e12fff1e` (bx lr).
//! The next real function starts with push {r4,lr} at 0x08116418.
//! Independent whole-image A32 decoding verifies two incoming plain BLs
//! (0x0819e29c, 0x082897cc), zero predicated BLs, and zero outgoing calls.
//!
//! Return the byte unchanged and zero-extended, without mutation or a NULL
//! guard. Both callers test zero/nonzero; the flag's domain meaning is not
//! established, so its existing offset-based field name is retained.
//! Deliberate deviations: none.

/// # Safety
/// `owner` must belong to a readable allocation including byte +0x4d3.
/// No alignment requirement or NULL guard, matching the original byte load.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_byte_at_4d3(owner: *const u8) -> u8 {
    owner.add(0x4d3).read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_all_unsigned_values_and_neighboring_bytes() {
        let mut owner = [0xa5; 0x4d5];
        owner[0x4d2] = 0x3c;
        owner[0x4d4] = 0xc3;
        for value in 0u8..=u8::MAX {
            owner[0x4d3] = value;
            let before = owner;
            assert_eq!(unsafe { owner_byte_at_4d3(owner.as_ptr()) }, value);
            assert_eq!(owner, before);
        }
    }

    #[test]
    fn accepts_unaligned_owner_with_exact_readable_extent() {
        #[repr(align(4))]
        struct Storage([u8; 0x4d5]);
        let mut storage = Storage([0x5a; 0x4d5]);
        storage.0[0x4d4] = 0xff;
        let owner = unsafe { storage.0.as_ptr().add(1) };
        assert_eq!(unsafe { owner_byte_at_4d3(owner) }, 0xff);
        assert_eq!(storage.0[0x4d3], 0x5a);
    }
}
