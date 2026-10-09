//! Counted dispatch-table address accessor.
//!
//! Original FUN_080c62fc @ 0x080c62fc, true extent 12 bytes:
//! `ldr r0, [pc, #0]; bx lr`, then literal 0x0896eda4 at 0x080c6304.
//! The next real function starts with `push {r4-r6, lr}` at 0x080c6308.
//! Full-image aligned A32 decoding verifies two inbound plain BLs
//! (0x080a5b9c, 0x080a5d28), zero predicated BLs, and no outbound calls.
//!
//! Return the fixed table address, without loading the word at that address.
//! Both callers pass it as r1 to FUN_080bf640, whose first two table words
//! are an entry count and a pointer to 12-byte dispatch records. The exact
//! dispatch-table identity and contents are unrecovered. Deliberate
//! deviations: none; hosts also return the opaque firmware address and must
//! not dereference it. No host data model or callee seam is needed.

/// Returns the firmware's counted dispatch table, not its first word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn counted_dispatch_table_address() -> *const u32 {
    0x0896_eda4usize as *const u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_exact_target_address_without_accessing_unmapped_firmware() {
        // The host has no firmware table here. Returning the address must
        // neither dereference it nor substitute host backing storage.
        assert_eq!(counted_dispatch_table_address() as usize, 0x0896_eda4);
    }
}
