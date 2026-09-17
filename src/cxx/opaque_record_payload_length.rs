//! `opaque_record_payload_length` — retailOS `FUN_082a1ec0` at `0x082a1ec0`.
//!
//! Raw ARM establishes the true eight-byte extent: `ldr r0, [r0, #8]; bx lr`
//! at `0x082a1ec0..0x082a1ec4`; the separately linked next leaf begins with
//! `ldr r0, [r0, #12]` at `0x082a1ec8`. Decoding every ARM B/BL-immediate word
//! in `osos.dec` finds four direct inbound calls, all unconditional plain `bl`
//! at `0x081043b8`, `0x081043f8`, `0x08104488`, and `0x081044ac`; no predicated
//! `bl` calls or direct-tail branches target this leaf.
//!
//! Algorithm: load and return the opaque record's target-width payload-length
//! word at byte offset eight. Deliberate deviations: none.

/// opaque_record_payload_length — retailOS `FUN_082a1ec0` at `0x082a1ec0`
/// (8 bytes; four unconditional plain-`bl` call sites, zero predicated).
///
/// The original has no NULL, alignment, or bounds guard. `record` must point
/// to a readable, four-byte-aligned opaque record with a word at byte offset 8.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_record_payload_length(record: *const u8) -> u32 {
    (record.add(8) as *const u32).read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_only_the_payload_length_word() {
        let record = [0x1020_3040u32, 0x5060_7080, 0x90a0_b0c0, 0xd0e0_f000];

        assert_eq!(unsafe { opaque_record_payload_length(record.as_ptr().cast()) }, 0x90a0_b0c0);
    }

    #[test]
    fn handles_zero_and_maximum_payload_lengths() {
        for payload_length in [0, u32::MAX] {
            let record = [0u32, 0xffff_ffff, payload_length, 0x1357_9bdf];

            assert_eq!(unsafe { opaque_record_payload_length(record.as_ptr().cast()) }, payload_length);
        }
    }
}
