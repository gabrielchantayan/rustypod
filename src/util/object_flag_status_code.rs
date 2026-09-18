//! Selects a status code from an object's flag words.
//!
//! `object_flag_status_code` is retailOS `FUN_080eeb7c` at load address
//! **0x080eeb7c**, 84 bytes (`0x080eeb7c..0x080eebd0`). The next independently
//! entered function starts with `push {r0-r6,lr}` at `0x080eebd0`. Decoding
//! `osos.dec` finds four direct inbound calls, all unconditional plain `bl` at
//! `0x08078428`, `0x0807ba48`, `0x08085f80`, and `0x080c8b64`; no predicated
//! `bl` calls target this entry. The body contains no `bl` instructions.
//!
//! # Algorithm
//!
//! The function reads the aligned primary flags at `object + 0x24`. A clear
//! primary bit 1, or a set secondary bit 2 at `+0x28` when primary bit 1 is
//! set, selects the fallback path. There, primary bit 0 and then bits 5–6
//! select status codes 3, 2, or 4. Outside that path, primary bit 4 selects
//! status 1; all remaining cases return 0.
//!
//! # Deliberate deviations
//!
//! None. Volatile reads retain the externally owned target-width object
//! accesses observed in the firmware.

const PRIMARY_FLAGS_OFFSET: usize = 0x24;
const SECONDARY_FLAGS_OFFSET: usize = 0x28;

/// Returns the status selected by the object's primary and secondary flags.
///
/// Original: `FUN_080eeb7c` at load address `0x080eeb7c`, 84 bytes, four
/// verified plain-`bl` callers, and no outbound calls.
///
/// # Safety
///
/// `object` must be non-null and valid for aligned volatile `u32` reads at
/// offsets `+0x24` and, when primary bit 1 is set, `+0x28`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.object_flag_status_code")]
#[inline(never)]
pub unsafe extern "C" fn object_flag_status_code(object: *const u8) -> u32 {
    let primary_flags = unsafe { (object.add(PRIMARY_FLAGS_OFFSET) as *const u32).read_volatile() };

    if primary_flags & 2 == 0
        || unsafe { (object.add(SECONDARY_FLAGS_OFFSET) as *const u32).read_volatile() } & 4 != 0
    {
        if primary_flags & 1 != 0 {
            if primary_flags & 0x10 != 0 {
                return 1;
            }
            return 0;
        }
        if primary_flags & 0x60 == 0x60 {
            return 3;
        }
        if primary_flags & 2 == 0 {
            return 2;
        }
        return 4;
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct FlagObject {
        _prefix: [u32; PRIMARY_FLAGS_OFFSET / 4],
        primary_flags: u32,
        secondary_flags: u32,
    }

    const _: () = assert!(core::mem::offset_of!(FlagObject, primary_flags) == PRIMARY_FLAGS_OFFSET);
    const _: () = assert!(core::mem::offset_of!(FlagObject, secondary_flags) == SECONDARY_FLAGS_OFFSET);

    fn status(primary_flags: u32, secondary_flags: u32) -> u32 {
        let object = FlagObject {
            _prefix: [0; PRIMARY_FLAGS_OFFSET / 4],
            primary_flags,
            secondary_flags,
        };
        unsafe { object_flag_status_code((&object as *const FlagObject).cast()) }
    }

    #[test]
    fn fallback_path_selects_all_three_codes() {
        assert_eq!(status(0, 0), 2);
        assert_eq!(status(0x60, 0), 3);
        assert_eq!(status(2, 4), 4);
    }

    #[test]
    fn primary_bit_zero_and_bit_four_override_the_fallback_statuses() {
        assert_eq!(status(1, 0), 0);
        assert_eq!(status(0x11, 0), 1);
        assert_eq!(status(0x13, 4), 1);
    }

    #[test]
    fn set_primary_bit_one_with_clear_secondary_bit_two_returns_zero() {
        for primary_flags in [2, 0x12, 0x62, u32::MAX] {
            assert_eq!(status(primary_flags, 0), 0, "primary flags {primary_flags:#010x}");
        }
    }
}
