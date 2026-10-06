//! Select the runtime active-entry table address.
//!
//! FUN_08165e34 @ 0x08165e34: true extent 56 bytes through 0x08165e6c,
//! where the next function begins (40 instruction bytes, 16 literal bytes).
//! Raw A32 verifies zero outgoing plain/predicated BLs and two incoming
//! plain BLs at 0x0815382c and 0x08153858, with no predicated incoming BLs.
//! Ignore the owner argument; nonzero enabled/primary flags select one of
//! four table bases. The caller serializes entries from the selected table.
//! Deliberate deviations: return a fixed-width firmware address rather than
//! a host pointer. No table contents are read or copied; no callee seam is
//! needed. All nonzero flag values retain the original true semantics.

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn active_entry_table_address(
    _owner: *const core::ffi::c_void, enabled: u32, primary: u32,
) -> u32 {
    match (enabled != 0, primary != 0) {
        (true, true) => 0x08a0_e738,
        (true, false) => 0x08a0_e7a0,
        (false, true) => 0x08a0_e7f0,
        (false, false) => 0x08a0_e818,
    }
}

#[cfg(test)]
mod tests {
    use super::active_entry_table_address;

    #[test]
    fn selects_each_table_for_zero_and_noncanonical_true_flags() {
        for enabled in [0, 1, 2, 0x8000_0000, u32::MAX] {
            for primary in [0, 1, 2, 0x8000_0000, u32::MAX] {
                // Reference follows the original conditional literal loads.
                let expected = if enabled != 0 {
                    if primary == 0 { 0x08a0_e7a0 } else { 0x08a0_e738 }
                } else if primary == 0 {
                    0x08a0_e818
                } else {
                    0x08a0_e7f0
                };
                for owner in [core::ptr::null(), 1usize as *const core::ffi::c_void] {
                    assert_eq!(active_entry_table_address(owner, enabled, primary), expected);
                }
            }
        }
    }
}
