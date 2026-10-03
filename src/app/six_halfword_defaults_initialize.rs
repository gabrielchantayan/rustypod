//! `six_halfword_defaults_initialize` — original `FUN_08270444` @ `0x08270444`.
//!
//! True size: 36 bytes (`0x08270444..0x08270468`); the next function starts
//! with `stmdb sp!,{r4,r5,r6,lr}` at `0x08270468`. Raw ARM words establish
//! five consecutive halfword stores of `0xffff`, then one of `0x0080` at
//! byte offset 10, followed by `bx lr`. No outbound calls. Independently
//! decoded inbound calls: 2 plain BL (0x0827104c, 0x08271054), 0 predicated BL.
//!
//! Returns the unchanged input pointer: the caller advances the preserved r0
//! by 0x14 between calls, then subtracts 0x50 to recover its containing object.
//! Deliberate deviation from Ghidra's void signature: expose this required
//! register pass-through. Field meanings remain unknown; no domain labels
//! are inferred from their sentinel values. No algorithmic deviations.

/// Initializes a six-halfword record to its retailOS defaults.
///
/// # Safety
/// `record` must be aligned for `u16` and valid for six consecutive writes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn six_halfword_defaults_initialize(record: *mut u16) -> *mut u16 {
    record.write(0xffff);
    record.add(1).write(0xffff);
    record.add(2).write(0xffff);
    record.add(3).write(0xffff);
    record.add(4).write(0xffff);
    record.add(5).write(0x0080);
    record
}

#[cfg(test)]
mod tests {
    use super::six_halfword_defaults_initialize;

    #[test]
    fn overwrites_defaults_at_both_halfword_alignments_without_touching_neighbors() {
        #[repr(C, align(4))]
        struct Buffer([u16; 10]);

        for start in [1, 2] {
            for fill in [0, 0xffff, 0x5aa5] {
                let mut buffer = Buffer([fill; 10]);
                let record = unsafe { buffer.0.as_mut_ptr().add(start) };
                let returned = unsafe { six_halfword_defaults_initialize(record) };
                assert_eq!(returned, record);
                let mut expected = [fill; 10];
                expected[start..start + 6].copy_from_slice(&[0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x0080]);
                assert_eq!(buffer.0, expected);
            }
        }
    }

    #[test]
    fn preserves_caller_pointer_chain_and_gap() {
        let mut words = [0x1234u16; 46];
        let base = words.as_mut_ptr();
        unsafe {
            let first = six_halfword_defaults_initialize(base.add(0x3c / 2));
            let second = six_halfword_defaults_initialize(first.add(0x14 / 2));
            assert_eq!(second.sub(0x50 / 2), base);
        }
        let mut expected = [0x1234u16; 46];
        expected[30..36].copy_from_slice(&[0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x0080]);
        expected[40..46].copy_from_slice(&[0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x0080]);
        assert_eq!(words, expected);
    }
}
