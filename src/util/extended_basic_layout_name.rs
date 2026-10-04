//! Returns the firmware's `Extended_Basic_Layout` name address.
//!
//! `extended_basic_layout_name` — `FUN_081fd610` @ **0x081fd610**.
//! True extent: **12 bytes**, 0x081fd610..0x081fd61c exclusive: eight
//! executable bytes (`ldr r0, [pc]`; `bx lr`) and literal 0x089cb23c.
//! Whole-image aligned A32 decoding verifies two plain inbound BLs at
//! 0x0803c2bc and 0x0805bb84, zero predicated inbound BLs, and no outbound BLs.
//! Return the fixed pointer without reading the pointed-to bytes. Raw firmware
//! at that address contains `Extended_Basic_Layout\0`. Both direct callers
//! pass it to `indexed_record_defaults`, which ignores its first argument.
//!
//! Deliberate deviations: none in observable behavior. LLVM may materialize
//! the address differently; the host also receives this target address, not
//! a substitute host string. It must not be dereferenced outside retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn extended_basic_layout_name() -> *const u8 {
    0x089c_b23cusize as *const u8
}

#[cfg(test)]
mod tests {
    use super::extended_basic_layout_name;

    #[test]
    fn returns_exact_target_address_without_accessing_target_memory() {
        // No fixture is mapped: the accessor must return an address, not load
        // a word from it or replace it with a host-resident string pointer.
        assert_eq!(extended_basic_layout_name() as usize, 0x089c_b23c);
    }
}
