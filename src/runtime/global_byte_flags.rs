//! Global byte-flag scan — FUN_08047eac @ 0x08047eac.
//!
//! True extent: 48 bytes through 0x08047edc (44-byte code plus the literal
//! at 0x08047ed8); the next function begins with PUSH at 0x08047edc.
//! Whole-image A32 decoding verifies two incoming plain BL calls at
//! 0x081a5460 and 0x08289854, no predicated BL calls, and no outgoing calls.
//!
//! Scans exactly 61 bytes at 0x08a11f50 in ascending order, returning u32 1
//! at the first nonzero byte or 0 if all are zero. The callers use the result
//! as a predicate; the table's subsystem identity is not established.
//! Deliberate deviations: volatile byte reads preserve live-state observation
//! and early exit; host builds substitute private backing for the fixed global.

const FLAG_COUNT: usize = 61;

#[cfg(not(target_os = "none"))]
static mut GLOBAL_BYTE_FLAGS: [u8; FLAG_COUNT] = [0; FLAG_COUNT];

/// Tests the fixed global byte table without reading beyond its 61 entries.
/// The caller must ensure the table is readable and externally synchronized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn global_byte_flags_any_set() -> u32 {
    #[cfg(target_os = "none")]
    let flags = core::ptr::without_provenance::<u8>(0x08a1_1f50);
    #[cfg(not(target_os = "none"))]
    let flags = core::ptr::addr_of!(GLOBAL_BYTE_FLAGS).cast::<u8>();

    let mut index = 0;
    while index < FLAG_COUNT {
        if flags.add(index).read_volatile() != 0 {
            return 1;
        }
        index += 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_table_and_every_position_with_all_nonzero_byte_values() {
        unsafe {
            let flags = core::ptr::addr_of_mut!(GLOBAL_BYTE_FLAGS).cast::<u8>();
            assert_eq!(global_byte_flags_any_set(), 0);
            for index in 0..FLAG_COUNT {
                for value in 1..=u8::MAX {
                    flags.add(index).write(value);
                    assert_eq!(global_byte_flags_any_set(), 1);
                }
                flags.add(index).write(0);
                assert_eq!(global_byte_flags_any_set(), 0);
            }
            for index in 0..FLAG_COUNT {
                flags.add(index).write(0xff);
            }
            assert_eq!(global_byte_flags_any_set(), 1);
            for index in 0..FLAG_COUNT {
                flags.add(index).write(0);
            }
        }
    }
}
