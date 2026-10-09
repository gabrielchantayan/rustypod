//! Counted dispatch-table address accessor, distinguished by its table address.
//!
//! Original FUN_080c62e4 @ 0x080c62e4, true extent 12 bytes (8 code,
//! 4 literal): words e59f0000 e12fff1e 089586d0. Decode as
//! `ldr r0, [pc, #0]; bx lr`; literal at 0x080c62ec, next real
//! function at 0x080c62f0. Full-image aligned A32 decoding verifies
//! two inbound plain BLs (0x080a5b84, 0x080a5c90), zero predicated
//! BLs, and no outbound calls.
//!
//! Returns 0x089586d0 itself, not the word stored there. Both callers
//! select this table for selector 7 and pass it in r1 to FUN_080bf640,
//! which interprets the first two words as a count and a pointer to
//! 12-byte dispatch records. Exact table identity remains unrecovered;
//! no callee seam or data reconstruction is needed.
//! Deliberate deviations: none. Hosts retain the opaque firmware address
//! and must not dereference it; no host backing storage is substituted.

/// Returns the counted dispatch table at firmware address 0x089586d0.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn counted_dispatch_table_address_9586d0() -> *const u32 {
    0x0895_86d0usize as *const u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_table_address_without_loading_contents_or_neighbor_literal() {
        // No firmware mapping exists on the host. A load through this
        // address would be invalid; returning table contents is not the ABI.
        assert_eq!(counted_dispatch_table_address_9586d0() as usize, 0x0895_86d0);
    }
}
