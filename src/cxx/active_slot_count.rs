//! Contiguous active-slot count — retailOS `FUN_0829cff8` @ `0x0829cff8`.
//!
//! Raw `osos.dec` establishes the true 60-byte extent
//! `0x0829cff8..0x0829d034`; `0x0829d034` starts the next leaf (`mov r0,#21`).
//! Decoding the function's 15 A32 words finds no outbound BL instructions.
//! Decoding inbound branch-with-link words finds four plain BL callers and no
//! predicated BL callers. Each slot is 20 target bytes, with its active flag
//! at offset +16. The function returns the number of consecutive active slots
//! from slot zero, stopping at the first clear flag or after four slots.
//!
//! Deliberate deviation: the unrecovered slot payload remains an opaque byte
//! layout rather than an invented Rust type; byte addressing preserves the
//! target's 20-byte stride and +16 flag offset on 64-bit hosts. LLVM unrolls
//! the fixed four-iteration loop, an equivalent code-generation deviation.

/// active_slot_count — original: `FUN_0829cff8` @ `0x0829cff8` (60 bytes;
/// four plain BL callers, no predicated BL callers). See the module header.
///
/// # Safety
///
/// `slots` must point to at least four readable 20-byte target-layout slots.
/// Neither the pointer nor any flag byte is NULL-checked by retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn active_slot_count(slots: *const u8) -> u8 {
    let mut slot_index = 0u8;
    while slot_index < 4 {
        if slots
            .add(slot_index as usize * 0x14 + 0x10)
            .read_volatile()
            == 0
        {
            return slot_index;
        }
        slot_index += 1;
    }

    slot_index
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOT_STRIDE: usize = 0x14;
    const ACTIVE_OFFSET: usize = 0x10;

    fn slot_flags(flags: [u8; 4]) -> [u8; SLOT_STRIDE * 4] {
        let mut slots = [0u8; SLOT_STRIDE * 4];
        for (index, flag) in flags.into_iter().enumerate() {
            slots[index * SLOT_STRIDE + ACTIVE_OFFSET] = flag;
        }
        slots
    }

    #[test]
    fn stops_at_each_possible_first_inactive_slot() {
        for (flags, expected) in [
            ([0, 1, 1, 1], 0),
            ([1, 0, 1, 1], 1),
            ([1, 1, 0, 1], 2),
            ([1, 1, 1, 0], 3),
        ] {
            let slots = slot_flags(flags);
            assert_eq!(unsafe { active_slot_count(slots.as_ptr()) }, expected);
        }
    }

    #[test]
    fn counts_all_four_nonzero_flags() {
        let slots = slot_flags([1, 0xff, 2, 0x80]);

        assert_eq!(unsafe { active_slot_count(slots.as_ptr()) }, 4);
    }

    #[test]
    fn ignores_payload_bytes_and_only_reads_flag_offsets() {
        let mut slots = [0xffu8; SLOT_STRIDE * 4];
        slots[ACTIVE_OFFSET] = 0;

        assert_eq!(unsafe { active_slot_count(slots.as_ptr()) }, 0);
    }
}
