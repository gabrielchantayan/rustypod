//! Counted dispatch-table address accessor, distinguished by its table address.
//!
//! Original FUN_080c62f0 @ 0x080c62f0, true extent 12 bytes (8 code,
//! 4 literal): words e59f0000 e12fff1e 08946ea4. Decode as
//! `ldr r0, [pc, #0]; bx lr`, with literal at 0x080c62f8; the next
//! real function starts at 0x080c62fc, not at the literal.
//! Full-image aligned A32 decoding verifies two inbound plain BLs
//! (0x080a5b8c, 0x080a5cb0), zero predicated BLs, no outbound calls.
//!
//! Return 0x08946ea4 itself, not the word stored there. Both callers
//! pass it in r1 to FUN_080bf640, which reads a count and a pointer to
//! 12-byte dispatch records from the first two table words. The table's
//! exact identity is unrecovered; the address suffix distinguishes this
//! accessor from the existing accessor for 0x0896eda4. No callee seam.
//! Deliberate deviations: none. Hosts preserve the opaque firmware address
//! and must not dereference it; no host backing storage is substituted.

/// Returns the counted dispatch table at firmware address 0x08946ea4.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn counted_dispatch_table_address_946ea4() -> *const u32 {
    0x0894_6ea4usize as *const u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_address_not_zero_table_contents_or_neighbor_table() {
        // Firmware backing storage is absent on the host. The accessor
        // must not load the table's zero first word or return its neighbor.
        assert_eq!(counted_dispatch_table_address_946ea4() as usize, 0x0894_6ea4);
    }
}
