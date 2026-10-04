//! Opaque-record member address — retailOS `FUN_0820be7c` at `0x0820be7c`.
//!
//! True size: 8 bytes. Raw words `e2800004 e12fff1e` decode as
//! `add r0,r0,#4; bx lr`. The next real function starts at `0x0820be84`
//! with `ldr r0,[r0,#0x10]; bx lr`. Independent whole-image ARM BL
//! decoding finds two plain unconditional inbound calls (0x082809c4 and
//! 0x08280ce0), zero predicated inbound calls, and no outgoing calls.
//!
//! Algorithm: return the address four bytes past the opaque record without
//! reading memory or validating the input. Both callers pass object +0x3c;
//! one forwards the returned address to 0x08162668, the other reads its
//! +4 word. Neither establishes a concrete member type or callee identity.
//!
//! Deliberate deviations: host pointer arithmetic wraps at the host pointer
//! width rather than ARM's 32 bits. Byte pointers retain the four-byte offset
//! on either target, including null, unaligned, and non-dereferenceable input.

/// Return the unchecked address of the opaque record's +4 member.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_record_member_at_04")]
#[inline(never)]
pub extern "C" fn opaque_record_member_at_04(record: *const u8) -> *const u8 {
    record.wrapping_add(4)
}

#[cfg(test)]
mod tests {
    use super::opaque_record_member_at_04;

    #[test]
    fn locates_member_in_embedded_record_with_four_byte_spacing() {
        let owner = [0x1111_1111u32; 20];
        let record = owner.as_ptr().wrapping_add(15).cast::<u8>();
        let member = opaque_record_member_at_04(record);
        assert_eq!(member, owner.as_ptr().wrapping_add(16).cast::<u8>());
        // The second caller reads the word four bytes beyond this member.
        assert_eq!(member.wrapping_add(4), owner.as_ptr().wrapping_add(17).cast::<u8>());
    }

    #[test]
    fn performs_no_access_or_validation_and_wraps_address_arithmetic() {
        for address in [0usize, 1, 2, 3, 0x0800_003c, usize::MAX - 4,
                        usize::MAX - 3, usize::MAX] {
            assert_eq!(opaque_record_member_at_04(address as *const u8) as usize,
                       address.wrapping_add(4));
        }
    }
}
