//! Optional relocated record-table address — `FUN_0829879c` @ **0x0829879c**.
//!
//! True size: **24 bytes**, ending at the next real function, 0x082987b4.
//! Raw A32: ldr r1,[r0,#0x64]; cmp r1,#0; ldrne r0,[r0,#0x58];
//! addne r0,r0,r1; moveq r0,#0; bx lr. Whole-image decoding verifies
//! two plain inbound BLs (0x08298750, 0x0829876c), zero predicated inbound
//! BLs, and zero outbound calls. The next function begins cmp r1,#0;
//! push {r4,lr}, matching the independently ported parser_stack_item.
//!
//! The caller indexes the returned table using 8- or 20-byte records.
//! Read the optional offset first; zero means absent, not the base address.
//! Otherwise add the target-width base and offset modulo 2^32. The concrete
//! owner type is not recovered. No deliberate behavioral deviations: fields
//! stay u32 on hosts, and neither NULL checks nor pointer validation is added.

/// Returns the target address of the optional record table.
///
/// # Safety
/// `owner` must be four-byte aligned and readable at word 25 (+0x64),
/// and at word 22 (+0x58) when the offset is nonzero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn relocated_record_table(owner: *const u32) -> u32 {
    let table_offset = unsafe { owner.add(25).read() };
    if table_offset == 0 {
        0
    } else {
        let data_base = unsafe { owner.add(22).read() };
        data_base.wrapping_add(table_offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_table_does_not_return_the_base() {
        for base in [0, 0x0800_0000, u32::MAX] {
            let mut owner = [0xa5a5_a5a5; 26];
            owner[22] = base;
            owner[25] = 0;
            assert_eq!(unsafe { relocated_record_table(owner.as_ptr()) }, 0);
        }
    }

    #[test]
    fn relocates_nonzero_offsets_with_target_width_wraparound() {
        for (base, offset, expected) in [
            (0x0800_0000, 0x120, 0x0800_0120),
            (0, 1, 1),
            (u32::MAX, 1, 0),
            (0x8000_0000, 0x8000_0001, 1),
            (0x0800_0000, u32::MAX, 0x07ff_ffff),
        ] {
            let mut owner = [0xa5a5_a5a5; 26];
            owner[22] = base;
            owner[25] = offset;
            let before = owner;
            assert_eq!(unsafe { relocated_record_table(owner.as_ptr()) }, expected);
            assert_eq!(owner, before);
        }
    }
}
