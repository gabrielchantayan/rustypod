//! Returns a block-manager client's requested byte limit.
//!
//! `client_byte_limit` — original: `FUN_081fbe44` @ 0x081fbe44 (**8 bytes**;
//! **3 verified plain `bl` call sites** at 0x08207960, 0x08207988, and
//! 0x082079f4; **no predicated `bl` call sites**). Raw ARM establishes the
//! exact extent `0x081fbe44..0x081fbe4c`: `ldr r0, [r0, #0x48]; bx lr`.
//! It returns the u32 byte-limit field at client offset +0x48; its three
//! calls in the block-manager balancing loop use that value as a byte count.
//!
//! # Deliberate deviations
//!
//! None.

/// client_byte_limit — original: `FUN_081fbe44` @ 0x081fbe44 (8 bytes).
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.client_byte_limit")]
#[inline(never)]
pub unsafe extern "C" fn client_byte_limit(client: *const u8) -> u32 {
    (client.add(0x48) as *const u32).read()
}

#[cfg(test)]
mod tests {
    use super::client_byte_limit;

    #[test]
    fn returns_the_client_byte_limit_field() {
        let mut client = [0u32; 19];

        for expected in [0, 1, 0x40000, u32::MAX] {
            client[0x48 / core::mem::size_of::<u32>()] = expected;
            assert_eq!(unsafe { client_byte_limit(client.as_ptr().cast()) }, expected);
        }
    }
}
