//! Select the byte length of a serialized active-entry buffer.
//!
//! FUN_0815378c @ 0x0815378c: true size 16 bytes, four A32 instructions
//! before the independent PUSH prologue at 0x0815379c. Raw words verify
//! two incoming plain BLs (0x08213cdc, 0x08213d38), no incoming predicated
//! BLs, and zero outgoing plain/predicated BLs.
//! Nonzero enabled loads word 1 (+4); zero loads word 3 (+12). The
//! neighboring serializer stores buffer addresses in words 0/2 and byte
//! lengths in words 1/3. The caller encodes each selected length as two
//! little-endian bytes; this getter itself returns the entire u32.
//! Deliberate deviations: none. Word indices preserve target offsets on
//! hosts; no pointer fields or callee seams are needed.

/// # Safety
/// `buffers` must be word-aligned and readable at the selected word
/// (1 for nonzero `enabled`, 3 for zero). No other word is read.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn active_entry_serialized_size(buffers: *const u32, enabled: u32) -> u32 {
    buffers.add(if enabled != 0 { 1 } else { 3 }).read()
}

#[cfg(test)]
mod tests {
    use super::active_entry_serialized_size;

    #[test]
    fn selects_full_unsigned_lengths_for_all_flag_classes() {
        for (enabled_size, disabled_size) in [
            (0, u32::MAX), (u32::MAX, 0), (0x8000_0000, 0x0001_0000),
            (0x1234_5678, 0x9abc_def0),
        ] {
            let buffers = [0xdead_beef, enabled_size, 0xcafe_babe, disabled_size];
            for enabled in [0, 1, 2, 0x8000_0000, u32::MAX] {
                let expected = if enabled == 0 { disabled_size } else { enabled_size };
                assert_eq!(unsafe {
                    active_entry_serialized_size(buffers.as_ptr(), enabled)
                }, expected);
            }
        }
    }

    #[test]
    fn enabled_needs_only_the_first_length_slot() {
        let buffers = [0xdead_beef, 0x8000_ffff];
        assert_eq!(unsafe {
            active_entry_serialized_size(buffers.as_ptr(), u32::MAX)
        }, 0x8000_ffff);
    }
}
