//! Filters an object's status using its flag words and query mode.
//!
//! retailOS `FUN_08085f54`, load address **0x08085f54**, 144 bytes
//! (`0x08085f54..0x08085fe4`); the next function starts with push {r4,lr}.
//! Raw ARM words verify two inbound plain BLs at 0x080d406c and 0x080db7e4,
//! no predicated inbound BLs, and one outbound plain BL at 0x08085f80 to
//! `object_flag_status_code` (0x080eeb7c), with no predicated outbound BLs.
//!
//! Primary bit 2 blocks either mode unless +0x2c bit 2 permits it. Zero
//! mode selects 1, 2, or 0 using primary bit 3 and +0x30 bits 5 and 7.
//! Nonzero mode calls the existing status selector, then suppresses status 2
//! when primary bit 3 is clear, or requires +0x30 bit 1 when it is set.
//! Callers apply additional +0x28 masks only in zero mode; no stronger object
//! type or meaning for the numeric codes is established.
//!
//! Deliberate deviations: none. Aligned volatile u32 reads preserve conditional
//! accesses and the primary flag reload after the callee.
//! ARM release match: 38 instructions versus the original 36. LLVM uses a
//! callee-saved object pointer and arithmetic status masks instead of several
//! predicated returns; the gate, mode split, BL, reload and read paths remain.
//! Host execution is verified; no device execution was performed.
//!

use super::object_flag_status_code::object_flag_status_code;

/// Returns the filtered status for zero or nonzero `query_mode`.
///
/// # Safety
/// `object` must permit aligned u32 reads at +0x24, +0x28, +0x2c and +0x30
/// whenever the corresponding firmware branch accesses them.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.object_filtered_status_code")]
#[inline(never)]
pub unsafe extern "C" fn object_filtered_status_code(object: *const u8, query_mode: i32) -> u32 {
    let primary_flags = unsafe { (object.add(0x24) as *const u32).read_volatile() };
    if primary_flags & 4 != 0
        && unsafe { (object.add(0x2c) as *const u32).read_volatile() } & 4 == 0
    {
        return 0;
    }
    if query_mode == 0 {
        if primary_flags & 8 == 0 {
            return 1;
        }
        let filter_flags = unsafe { (object.add(0x30) as *const u32).read_volatile() };
        if filter_flags & 0x20 != 0 {
            return 1;
        }
        return if filter_flags & 0x80 != 0 { 2 } else { 0 };
    }
    let status = unsafe { object_flag_status_code(object) };
    if status == 0 {
        return 0;
    }
    let primary_flags = unsafe { (object.add(0x24) as *const u32).read_volatile() };
    if primary_flags & 8 == 0 {
        return if status == 2 { 0 } else { status };
    }
    if unsafe { (object.add(0x30) as *const u32).read_volatile() } & 2 != 0 {
        status
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(primary: u32, secondary: u32, gate: u32, filter: u32, mode: i32) -> u32 {
        if primary & 4 != 0 && gate & 4 == 0 { return 0; }
        if mode == 0 {
            return match (primary & 8 != 0, filter & 0x20 != 0, filter & 0x80 != 0) {
                (false, _, _) | (_, true, _) => 1,
                (_, _, true) => 2,
                _ => 0,
            };
        }
        let status = match (primary & 2 != 0 && secondary & 4 == 0,
                            primary & 1 != 0, primary & 0x10 != 0,
                            primary & 0x60 == 0x60, primary & 2 != 0) {
            (true, _, _, _, _) => 0,
            (_, true, true, _, _) => 1,
            (_, true, false, _, _) => 0,
            (_, false, _, true, _) => 3,
            (_, false, _, false, false) => 2,
            _ => 4,
        };
        match (primary & 8 != 0, filter & 2 != 0, status) {
            (false, _, 2) | (true, false, _) => 0,
            _ => status,
        }
    }

    #[test]
    fn all_relevant_flag_combinations_and_mode_boundaries() {
        for primary in 0..128 {
            for secondary in [0, 4] {
                for gate in [0, 4] {
                    for bits in 0..8 {
                        let filter = (bits & 1) * 2 | ((bits >> 1) & 1) * 0x20
                            | ((bits >> 2) & 1) * 0x80;
                        for mode in [0, 1, -1, i32::MIN, i32::MAX] {
                            for unrelated in [0, 0xffff_ff00] {
                                let mut object = [0u32; 13];
                                object[9] = primary | unrelated;
                                object[10] = secondary | unrelated;
                                object[11] = gate | unrelated;
                                object[12] = filter | unrelated;
                                let result = unsafe {
                                    object_filtered_status_code(object.as_ptr().cast(), mode)
                                };
                                assert_eq!(result, reference(primary, secondary, gate, filter, mode),
                                    "primary={primary:#x} secondary={secondary:#x} gate={gate:#x} filter={filter:#x} mode={mode}");
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn blocked_query_reads_only_the_gate_and_zero_mode_can_use_short_object() {
        let mut blocked = [0u32; 12];
        blocked[9] = 4;
        for mode in [0, 1, -1] {
            assert_eq!(unsafe { object_filtered_status_code(blocked.as_ptr().cast(), mode) }, 0);
        }
        let short = [0u32; 10];
        assert_eq!(unsafe { object_filtered_status_code(short.as_ptr().cast(), 0) }, 1);
    }
}
