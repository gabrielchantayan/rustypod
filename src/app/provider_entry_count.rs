//! Provider entry count — retailOS `FUN_081c1cdc` @ `0x081c1cdc`.
//!
//! Raw words e590001c, e5900004, e12fff1e establish the true 12-byte
//! extent [0x081c1cdc,0x081c1ce8). The next function loads r2 from r1+16
//! at 0x081c1ce8 and returns independently at 0x081c1d10.
//! Whole-image A32 decoding finds two inbound plain BLs (0x0827b378,
//! 0x0827b448), zero predicated BLs, and a BNE tail entry at 0x0827b314.
//! There are no outbound calls. Follow the target pointer at provider+0x1c
//! and return the unchanged word at state+4. Callers use it to allocate
//! and bounds-check 16-byte entries; the wrapper interprets it as signed.
//!
//! Deliberate deviation: LLVM adds an fp/lr frame around the same two loads.
//! Opaque fields remain target-width words; no class or NULL handling invented.

/// Returns the provider's entry count, preserving all 32 result bits.
///
/// Original: 0x081c1cdc, 12 bytes, two plain BL callers, no predicated BLs.
///
/// # Safety
/// `provider` must be word-aligned and readable through +0x1c. Its word
/// at +0x1c must name word-aligned storage readable through +4. Neither
/// pointer is NULL-checked by retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn provider_entry_count(provider: *const u8) -> i32 {
    let count_state = provider.cast::<u32>().add(7).read();
    (count_state as usize as *const i32).add(1).read()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn preserves_count_bits_and_follows_changed_state_pointer() {
        let Some(base) = try_map_u32_slab(hints::PROVIDER_ENTRY_COUNT, 0x1000) else {
            assert!(note_missing_u32_fixture("app::provider_entry_count"));
            return;
        };
        unsafe {
            let provider = base.cast::<u32>();
            let first = base.add(0x100).cast::<i32>();
            let second = base.add(0x200).cast::<i32>();
            for index in 0..8 {
                provider.add(index).write(0xdead_beef);
            }
            first.write(123);
            second.write(456);
            second.add(1).write(17);
            for count in [0, 1, -1, -2, i32::MIN, i32::MAX] {
                first.add(1).write(count);
                provider.add(7).write(first as usize as u32);
                assert_eq!(provider_entry_count(base), count);
                provider.add(7).write(second as usize as u32);
                assert_eq!(provider_entry_count(base), 17);
            }
        }
    }
}
