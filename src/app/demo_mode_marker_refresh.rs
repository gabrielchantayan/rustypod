//! Refresh demo-mode marker flags — `FUN_081d2bbc` @ 0x081d2bbc.
//!
//! True extent: 216 bytes, 0x081d2bbc..0x081d2c94: 192 bytes of A32
//! code and 24 bytes of literals. Raw words verify two outbound plain BLs,
//! zero predicated BLs, and two inbound plain BLs (zero predicated).
//! Decode word-shifted `Demo Mode Silent` and `Demo Mode` strings. Probe
//! the silent marker with flags zero, write its low byte at global +0x19,
//! and only on a full-word zero result probe the ordinary marker. Write
//! the boolean OR of the full query results at global +0x18.
//! Deliberate deviation: fold constant decoding and NUL termination into
//! static strings, removing stack copies and loops. Call the existing
//! path_exists port directly; preserve query and volatile-store ordering.

const SILENT_MARKER: &[u8; 17] = b"Demo Mode Silent\0";
const DEMO_MARKER: &[u8; 10] = b"Demo Mode\0";
const DEVICE_FLAGS_ADDRESS: usize = 0x089c_af44;

#[inline(always)]
unsafe fn refresh_flags(
    device_flags: *mut u8,
    mut query: impl FnMut(*const u8, u32) -> u32,
) {
    let silent = query(SILENT_MARKER.as_ptr(), 0);
    device_flags.add(0x19).write_volatile(silent as u8);
    let enabled = silent != 0 || query(DEMO_MARKER.as_ptr(), 0) != 0;
    device_flags.add(0x18).write_volatile(enabled as u8);
}

/// Refresh both demo-mode marker flags from the retail filesystem.
///
/// # Safety
/// RetailOS filesystem and device globals must be initialized and accessible.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn demo_mode_marker_refresh() {
    refresh_flags(DEVICE_FLAGS_ADDRESS as *mut u8, |path, flags| {
        crate::app::path_exists::path_exists(path, flags)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_word_results_control_fallback_and_only_two_flags_change() {
        // Independent reconstruction from the firmware's encoded literal words.
        let encoded = [0xdeda_ca88u32, 0xc8de_9a40, 0xd2a6_40ca, 0xe8dc_cad8];
        let mut silent_path = [0u8; 17];
        for (index, word) in encoded.iter().enumerate() {
            silent_path[index * 4..index * 4 + 4]
                .copy_from_slice(&(word >> 1).to_le_bytes());
        }
        let ordinary_words = [0xdeda_ca88u32, 0xc8de_9a40, 0xb0b0_b0ca];
        let mut ordinary_path = [0u8; 12];
        for (index, word) in ordinary_words.iter().enumerate() {
            ordinary_path[index * 4..index * 4 + 4]
                .copy_from_slice(&(word >> 1).to_le_bytes());
        }
        ordinary_path[9] = 0; // Original STRB at sp+29.

        for (silent, ordinary, enabled) in [
            (0, 0, 0), (0, 0x100, 1), (0, 0xffff_ff82, 1),
            (1, 0, 1), (0x100, 0, 1), (0xffff_ff82, 0, 1),
        ] {
            let mut flags = [0xa5u8; 0x40];
            let ptr = flags.as_mut_ptr();
            let mut calls = 0;
            unsafe {
                refresh_flags(ptr, |path, query_flags| {
                    assert_eq!(query_flags, 0);
                    calls += 1;
                    assert_eq!(ptr.add(0x18).read(), 0xa5);
                    if calls == 1 {
                        assert_eq!(core::slice::from_raw_parts(path, 17), silent_path);
                        assert_eq!(ptr.add(0x19).read(), 0xa5);
                        silent
                    } else {
                        assert_eq!(calls, 2);
                        assert_eq!(core::slice::from_raw_parts(path, 10), &ordinary_path[..10]);
                        assert_eq!(ptr.add(0x19).read(), 0);
                        ordinary
                    }
                });
            }
            assert_eq!(calls, if silent == 0 { 2 } else { 1 });
            let mut expected = [0xa5u8; 0x40];
            expected[0x19] = silent as u8;
            expected[0x18] = enabled;
            assert_eq!(flags, expected);
        }
    }
}
