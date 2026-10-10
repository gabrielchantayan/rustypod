//! Counted dispatch-table address accessor.
//!
//! Original FUN_080bd7ec @ 0x080bd7ec, true extent 12 bytes:
//! `ldr r0, [pc, #0]; bx lr`, then literal 0x0896bc48 at 0x080bd7f4.
//! The executable body is 8 bytes; the next real function starts with
//! `push {r4-r6, lr}` at 0x080bd7f8. Full-image aligned A32 decoding
//! verifies two inbound plain BLs (0x080a5b94, 0x080a5cfc), zero
//! predicated BLs, and no outbound calls.
//!
//! Return the fixed table address without reading the table. Both callers
//! pass it as r1 to FUN_080bf640, which reads an entry count and a pointer
//! to 12-byte dispatch records from the first two words. The specific table
//! identity and contents remain unrecovered. Deliberate deviations: none;
//! hosts return the opaque target address too, without dereferencing it.

/// Returns the firmware counted dispatch table, not the word stored there.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn counted_dispatch_table_address_96bc48() -> *const u32 {
    0x0896_bc48usize as *const u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_target_address_without_dereferencing_unmapped_table() {
        // No host backing storage: a mistaken table load would fault here.
        assert_eq!(counted_dispatch_table_address_96bc48() as usize, 0x0896_bc48);
    }
}
