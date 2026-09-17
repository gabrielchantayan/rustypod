//! Opaque object flag-0x10 predicate — `FUN_082a5d44` @ 0x082a5d44 (16
//! bytes; 4 plain `bl` call sites, no predicated calls).
//!
//! Raw ARM establishes the four-word extent 0x082a5d44..0x082a5d50: `ldrb
//! r0,[r0,#0x18]; and r0,r0,#0x10; mov r0,r0,lsr #4; bx lr`; the separately
//! linked next function begins at 0x082a5d54 with `push {r1-r7,lr}`.
//! Decoding every aligned ARM branch word finds four inbound unconditional
//! calls at 0x081357d4, 0x081358ac, 0x0813596c, and 0x0815ef60, with no
//! predicated `bl` callers. It reads bit 4 of the opaque object's byte at
//! offset 0x18 and returns that bit normalized to 0 or 1. Deliberate
//! deviations: none.

/// Returns whether bit 4 is set in the opaque object's byte at offset 0x18.
///
/// # Safety
/// `object` must be valid to read at byte offset 0x18.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.object_flag_0x10_is_set")]
#[inline(never)]
pub unsafe extern "C" fn object_flag_0x10_is_set(object: *const u8) -> u32 {
    ((object.add(0x18).read() & 0x10) >> 4) as u32
}

#[cfg(test)]
mod tests {
    use super::object_flag_0x10_is_set;

    #[test]
    fn normalizes_the_offset_0x18_flag_bit() {
        for flags in [0u8, 1, 0x0f, 0x10, 0x11, 0xef, 0xff] {
            let mut object = [0xa5u8; 0x19];
            object[0x18] = flags;

            assert_eq!(unsafe { object_flag_0x10_is_set(object.as_ptr()) }, u32::from(flags & 0x10 != 0));
            assert!(object[..0x18].iter().all(|&byte| byte == 0xa5));
        }
    }
}
