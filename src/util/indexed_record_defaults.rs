//! Copies an indexed firmware default record into an object.
//!
//! `indexed_record_defaults` — `FUN_081fd61c` @ **0x081fd61c**.
//! True extent: **68 bytes**, 0x081fd61c..0x081fd660 exclusive: 64 code
//! bytes plus the table literal 0x089cb240. The next function is bx lr.
//! Raw A32 decoding finds two plain inbound BLs (0x0803c2c8 and
//! 0x0805bb90), zero predicated inbound BLs, and zero outbound calls.
//! Ignore r0; compute table + index * 20 with wrapping 32-bit arithmetic.
//! Copy source words 0..4 into destination offsets +4, +8, +16, +24,
//! +20 in that order; clear only byte +12; return zero in r0.
//!
//! Deliberate deviations: volatile accesses preserve the original ordered
//! reads/writes and byte-only clear. No bounds checks or table-content
//! interpretation are introduced; the runtime firmware table remains authoritative.
//!
//! # Safety
//! The selected firmware address must be readable for five aligned words.
//! `dst` must be aligned and writable for seven words. The ignored first
//! argument need not be valid. No destination fields outside those above change.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_record_defaults(
    _unused: u32, index: u32, dst: *mut u32,
) -> u32 {
    let address = 0x089c_b240u32.wrapping_add(index.wrapping_mul(20));
    let source = address as usize as *const u32;
    dst.add(1).write_volatile(source.read_volatile());
    dst.add(2).write_volatile(source.add(1).read_volatile());
    dst.add(4).write_volatile(source.add(2).read_volatile());
    dst.add(6).write_volatile(source.add(3).read_volatile());
    dst.add(5).write_volatile(source.add(4).read_volatile());
    dst.cast::<u8>().add(12).write_volatile(0);
    0
}

#[cfg(test)]
mod tests {
    use super::indexed_record_defaults;

    #[test]
    fn selects_records_preserves_other_bytes_and_wraps_index_arithmetic() {
        let hint = crate::testing::hints::INDEXED_RECORD_DEFAULTS;
        let Some(slab) = crate::testing::try_map_u32_slab(hint, 0x10000) else {
            crate::testing::note_missing_u32_fixture("indexed_record_defaults");
            return;
        };
        // The production entry uses a fixed firmware address, not a host seam.
        assert_eq!(slab as usize, hint, "fixed firmware table fixture unavailable");
        let records = [
            [0, 0xffff_ffff, 0x8000_0000, 0x1234_5678, 0xabcdef01],
            [11, 22, 33, 44, 55],
        ];
        unsafe {
            let table = slab.add(0xb240).cast::<u32>();
            for (i, record) in records.iter().enumerate() {
                for (j, word) in record.iter().enumerate() {
                    table.add(i * 5 + j).write(*word);
                }
            }
            for (index, selected) in [(0, 0), (1, 1), (0x4000_0000, 0), (0x4000_0001, 1)] {
                let mut actual = [0xa5a5_a5a5u32; 9];
                let mut expected = actual;
                for (source, destination) in [2, 3, 5, 7, 6].iter().enumerate() {
                    expected[*destination] = records[selected][source];
                }
                expected[4] &= 0xffff_ff00;
                assert_eq!(indexed_record_defaults(u32::MAX, index, actual.as_mut_ptr().add(1)), 0);
                assert_eq!(actual, expected);
            }
        }
    }
}
