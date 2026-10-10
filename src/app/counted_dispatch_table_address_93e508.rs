//! Counted dispatch-table address accessor, distinguished by its table address.
//!
//! Original FUN_080b3fd0 @ 0x080b3fd0, true extent 12 bytes (8 code,
//! 4 literal): words e59f0000 e12fff1e 0893e508. Decode as
//! `ldr r0, [pc, #0]; bx lr`, with literal at 0x080b3fd8; the next
//! real function starts with `push {r1-r11, lr}` at 0x080b3fdc.
//! Full-image aligned A32 decoding verifies two inbound plain BLs
//! (0x080a5b64, 0x080a5c44), zero predicated BLs, no outbound calls.
//!
//! Return 0x0893e508 itself, not the word stored there. Both callers
//! pass it in r1 to FUN_080bf640, which reads a count and a pointer to
//! 12-byte dispatch records from the first two table words. The table's
//! exact identity and contents are unrecovered; no callee seam is needed.
//! Deliberate deviations: none. Hosts preserve the opaque firmware address
//! and must not dereference it; no host backing storage is substituted.

/// Returns the counted dispatch table at firmware address 0x0893e508.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn counted_dispatch_table_address_93e508() -> *const u32 {
    0x0893_e508usize as *const u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_address_not_table_contents_or_neighbor_table() {
        // Firmware backing storage is absent on the host. This must return
        // the opaque address without loading its first word or another table.
        assert_eq!(counted_dispatch_table_address_93e508() as usize, 0x0893_e508);
    }
}
