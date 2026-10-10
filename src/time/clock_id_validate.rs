//! Clock dispatch ID validation — original @ 0x08084310.
//!
//! True size: 28 bytes, ending before the independent prologue at 0x0808432c.
//! Raw-word census: two inbound plain BLs (0x082c3748, 0x082c37bc), zero
//! predicated inbound BLs; zero outgoing plain or predicated BLs.
//! Four chained equality comparisons accept exactly IDs 0, 1, 2 and 3;
//! return zero for those IDs and error 26 for every other 32-bit value.
//! Deliberate deviation: express the equality chain as an unsigned range
//! check; signed negative IDs still fail. No behavioral deviations.

/// Validate a clock dispatch-table index without accessing the table.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn clock_id_validate(clock_id: i32) -> i32 {
    if (clock_id as u32) < 4 { 0 } else { 26 }
}

#[cfg(test)]
mod tests {
    use super::clock_id_validate;

    #[test]
    fn accepts_each_clock_slot_and_rejects_unsigned_boundaries() {
        for id in 0..4 {
            assert_eq!(clock_id_validate(id), 0);
        }
        for id in [4, 5, 26, 255, 65536, i32::MAX, i32::MIN, -4, -3, -2, -1] {
            assert_eq!(clock_id_validate(id), 26, "clock ID {id}");
        }
    }

    #[test]
    fn matches_original_equality_chain_across_low_and_high_bit_ids() {
        for low in 0..=255u32 {
            for upper in [0, 0x0001_0000, 0x7fff_ff00, 0x8000_0000, 0xffff_ff00] {
                let id = upper | low;
                let expected = match id { 0 | 1 | 2 | 3 => 0, _ => 26 };
                assert_eq!(clock_id_validate(id as i32), expected, "clock ID {id:#x}");
            }
        }
    }
}
