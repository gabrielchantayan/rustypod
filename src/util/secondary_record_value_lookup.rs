//! `secondary_record_value_lookup` — original: `FUN_080ffb2c` @ `0x080ffb2c`
//! (52 instruction bytes; `bx lr` at `0x080ffb5c`, followed by the literal
//! pool at `0x080ffb60` and a separate function at `0x080ffb64`).
//!
//! Raw ARM decoding finds three inbound direct calls, all unconditional plain
//! `bl` instructions (0x080ffe28, 0x08203b7c, and 0x08203c90); there are no
//! predicated `bl` forms. The function scans the 32 packed four-byte records
//! at 0x083e9d14 in order, comparing `key` to the unsigned halfword at +0x02
//! and returning the sign-extended halfword at +0x00 on the first match. It
//! returns `i32::MAX` when none matches. Host builds deliberately substitute a
//! private layout-identical table because the retail address is unmapped.

#[cfg(test)]
extern crate std;

const SECONDARY_RECORD_COUNT: usize = 0x20;
const SECONDARY_TABLE_ADDRESS: usize = 0x083e_9d14;
const NOT_FOUND: i32 = i32::MAX;

/// One packed record in the secondary retail lookup table.
#[repr(C)]
#[derive(Clone, Copy)]
struct SecondaryRecord {
    value: i16,
    key: u16,
}

const EMPTY_SECONDARY_RECORD: SecondaryRecord = SecondaryRecord { value: 0, key: 0 };
const _: [u8; 4] = [0; core::mem::size_of::<SecondaryRecord>()];
const _: [u8; 2] = [0; core::mem::offset_of!(SecondaryRecord, key)];

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn secondary_table() -> &'static [SecondaryRecord; SECONDARY_RECORD_COUNT] {
    unsafe { &*(SECONDARY_TABLE_ADDRESS as *const [SecondaryRecord; SECONDARY_RECORD_COUNT]) }
}

#[cfg(not(target_os = "none"))]
static HOST_SECONDARY_TABLE: [SecondaryRecord; SECONDARY_RECORD_COUNT] =
    [EMPTY_SECONDARY_RECORD; SECONDARY_RECORD_COUNT];

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn secondary_table() -> &'static [SecondaryRecord; SECONDARY_RECORD_COUNT] {
    &HOST_SECONDARY_TABLE
}

#[inline]
fn find_secondary_record_value(key: u32, table: &[SecondaryRecord; SECONDARY_RECORD_COUNT]) -> i32 {
    for record in table {
        if u32::from(record.key) == key {
            return i32::from(record.value);
        }
    }
    NOT_FOUND
}

/// Returns the signed value associated with `key` in the 32-record retail table.
///
/// # Safety
///
/// On the target, the retail table at 0x083e9d14 must retain its stock layout.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.secondary_record_value_lookup")]
#[inline(never)]
pub unsafe extern "C" fn secondary_record_value_lookup(key: u32) -> i32 {
    unsafe { find_secondary_record_value(key, secondary_table()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_the_first_matching_signed_value() {
        let mut table = [EMPTY_SECONDARY_RECORD; SECONDARY_RECORD_COUNT];
        table[0] = SecondaryRecord { value: -32768, key: 0x1234 };
        table[7] = SecondaryRecord { value: 99, key: 0x1234 };

        assert_eq!(find_secondary_record_value(0x1234, &table), -32768);
    }

    #[test]
    fn compares_the_full_u32_key_and_returns_not_found() {
        let mut table = [EMPTY_SECONDARY_RECORD; SECONDARY_RECORD_COUNT];
        table[31] = SecondaryRecord { value: 32767, key: 0xffff };

        assert_eq!(find_secondary_record_value(0xffff, &table), 32767);
        assert_eq!(find_secondary_record_value(0x1_ffff, &table), i32::MAX);
        assert_eq!(find_secondary_record_value(0, &table), 0);
        assert_eq!(find_secondary_record_value(1, &table), i32::MAX);
    }
}
