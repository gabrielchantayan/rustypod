//! Midpoint output of the retail settings scaling curve.
//!
//! FUN_08051e30 @ 0x08051e30: true extent [0x08051e30,0x08051e38),
//! 8 bytes. Raw words e3a00037 e12fff1e are MOV r0,#55; BX lr;
//! the next independent function starts with PUSH {r4,lr}.
//! Whole-image aligned ARM decoding verifies two incoming plain BLs
//! (0x080e677c, 0x08112798), zero predicated incoming BLs, and zero
//! outgoing plain or predicated BLs. No arguments, memory accesses,
//! or callees: return 55, the output at input 50 of settings_value_scale.
//! The other caller compares this value with 100 for query 0x63f8.
//! Deliberate deviations: none. LLVM may fold this immutable result
//! into callers; the exported leaf remains available as a hook target.

/// Return the immutable midpoint output, not the curve's maximum of 100.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn settings_scale_midpoint() -> u32 {
    55
}

#[cfg(test)]
mod tests {
    use super::settings_scale_midpoint;

    #[test]
    fn midpoint_is_fifty_five_not_the_maximum() {
        assert_eq!(settings_scale_midpoint(), 55);
    }
}
