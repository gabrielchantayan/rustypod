//! map_status_code — original: `FUN_0809da3c` @ 0x0809da3c (72 bytes;
//! 8 direct `bl` call sites, all unconditional).
//!
//! The raw ARM body begins at 0x0809da3c and ends with `bx lr` at
//! 0x0809da80; the following `push {r4-r11,lr}` at 0x0809da84 belongs to
//! the next function. It preserves every status except 2, 5, 7, 13, and 14,
//! which become -34, -38, -42, -48, and -36 respectively. The original's
//! signed `bgt` split after testing 7 is retained, so negative status values
//! pass through unchanged.
//!
//! A complete osos.dec decode finds eight direct inbound `bl` instructions,
//! all unconditional (0x0805a5ec, 0x0805a62c, 0x0805a6e0, 0x0805a874,
//! 0x0805a8a8, 0x0805a930, 0x0805a980, and 0x0805a9bc), no predicated `bl`,
//! and three non-call `bne` tail branches (0x0805a72c, 0x0805a768, and
//! 0x0805ae54). No deliberate deviations.

/// map_status_code — original: `FUN_0809da3c` @ 0x0809da3c (72 bytes).
///
/// Converts the five retailOS status codes with distinct caller-facing
/// meanings while passing every other signed status through unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[link_section = ".text.map_status_code"]
pub extern "C" fn map_status_code(status: i32) -> i32 {
    if status == 7 {
        -42
    } else if status > 7 {
        if status == 13 {
            -48
        } else if status == 14 {
            -36
        } else {
            status
        }
    } else if status == 0 {
        0
    } else if status == 2 {
        -34
    } else if status == 5 {
        -38
    } else {
        status
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_only_the_five_special_status_codes() {
        assert_eq!(map_status_code(2), -34);
        assert_eq!(map_status_code(5), -38);
        assert_eq!(map_status_code(7), -42);
        assert_eq!(map_status_code(13), -48);
        assert_eq!(map_status_code(14), -36);
    }

    #[test]
    fn preserves_non_special_and_signed_boundary_values() {
        for status in [i32::MIN, -1, 0, 1, 3, 4, 6, 8, 12, 15, i32::MAX] {
            assert_eq!(map_status_code(status), status, "status {status}");
        }
    }
}
