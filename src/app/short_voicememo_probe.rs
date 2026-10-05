//! Refresh the short-voicememo device flag — `FUN_081d50d4` @ 0x081d50d4.
//!
//! True extent: 176 bytes, 0x081d50d4..0x081d5184 (132 bytes of A32
//! code, then four encoded words, prefix text, and the global pointer).
//! Raw words verify three outbound plain BLs and zero predicated BLs;
//! two inbound plain BLs occur in the device-flag refresh dispatcher.
//! Shift each of four suffix words right by one, terminate the resulting
//! `_short_voicememo` string, concatenate `iPod_Control\\Device\\`, query
//! path_exists with flags zero, and store the low byte at global +0x2f.
//! Deliberate deviation: constant decoding and concatenation are folded
//! into a NUL-terminated literal; no allocation or temporary copy is needed.
//! The existing path_exists port supplies the filesystem query unchanged.

const MARKER_PATH: &[u8; 37] = b"iPod_Control\\Device\\_short_voicememo\0";
const DEVICE_FLAGS_ADDRESS: usize = 0x089c_af44;
const SHORT_VOICEMEMO_OFFSET: usize = 0x2f;

type PathQuery = unsafe extern "C" fn(*const u8, u32) -> u32;

#[inline(always)]
unsafe fn refresh_flag(device_flags: *mut u8, query: PathQuery) {
    let status = query(MARKER_PATH.as_ptr(), 0);
    device_flags.add(SHORT_VOICEMEMO_OFFSET).write_volatile(status as u8);
}

/// Probe the short-voicememo marker and overwrite its device flag.
///
/// # Safety
/// Must run within retailOS with its filesystem and device globals initialized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn short_voicememo_probe() {
    refresh_flag(DEVICE_FLAGS_ADDRESS as *mut u8, crate::app::path_exists::path_exists);
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn absent(path: *const u8, flags: u32) -> u32 {
        assert_eq!(flags, 0);
        // Reference reconstructed independently from the original literal words.
        let encoded = [0xded0_e6beu32, 0xecbe_e8e4, 0xcac6_d2de, 0xdeda_cada];
        let mut expected = [0u8; 37];
        let prefix = b"iPod_Control\\Device\\";
        expected[..prefix.len()].copy_from_slice(prefix);
        for (index, word) in encoded.iter().enumerate() {
            expected[prefix.len() + index * 4..prefix.len() + index * 4 + 4]
                .copy_from_slice(&(word >> 1).to_le_bytes());
        }
        assert_eq!(core::slice::from_raw_parts(path, expected.len()), expected);
        0
    }

    unsafe extern "C" fn high_bits_only(path: *const u8, flags: u32) -> u32 {
        absent(path, flags);
        0x1234_5600
    }

    unsafe extern "C" fn non_boolean_status(path: *const u8, flags: u32) -> u32 {
        absent(path, flags);
        0xffff_ff82
    }

    #[test]
    fn absent_marker_clears_only_the_selected_flag() {
        let mut flags = [0xa5u8; 0x40];
        unsafe { refresh_flag(flags.as_mut_ptr(), absent); }
        let mut expected = [0xa5u8; 0x40];
        expected[0x2f] = 0;
        assert_eq!(flags, expected);
    }

    #[test]
    fn query_status_is_truncated_not_booleanized() {
        for (query, byte) in [(high_bits_only as PathQuery, 0), (non_boolean_status as PathQuery, 0x82)] {
            let mut flags = [0x5au8; 0x40];
            unsafe { refresh_flag(flags.as_mut_ptr(), query); }
            let mut expected = [0x5au8; 0x40];
            expected[0x2f] = byte;
            assert_eq!(flags, expected);
        }
    }
}
