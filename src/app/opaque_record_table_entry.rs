//! Opaque eight-byte record-table accessor.
//!
//! `opaque_record_table_entry_at` — original: `FUN_0829c01c` @ `0x0829c01c`
//! (**12 bytes**, `0x0829c01c..0x0829c028`). Raw ARM is
//! `ldr r0,[r0,#0xc]; add r0,r0,r1,lsl #3; bx lr`; the separately entered
//! next function begins at `0x0829c028`.
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds **seven direct plain
//! unconditional `bl` calls**, at `0x08133808`, `0x08133828`, `0x08133864`,
//! `0x0813389c`, `0x081338d0`, `0x081339b8`, and `0x08133a18`; there are no
//! predicated `bl` calls. An unconditional non-call tail `b` at `0x0829ae50`
//! first advances its input by `0x4c` and then transfers here. No aligned raw
//! data word names this function.
//!
//! The table's word at `+0x0c` is the base of opaque eight-byte records. This
//! accessor returns `base + 8 * index`, with ARM's wrapping word arithmetic;
//! it deliberately performs no NULL, bounds, or alignment checks. The record
//! contents and table's leading three words are not recovered, so they remain
//! opaque. No deliberate deviations.

/// The recovered prefix of a table of opaque eight-byte records.
///
/// `entries` is the target's aligned word at `+0x0c`. Its named field keeps
/// the target layout correct while allowing host pointer fields to widen.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpaqueRecordTable {
    pub prefix_words: [u32; 3],
    pub entries: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(OpaqueRecordTable, entries)];

/// Returns the opaque eight-byte record at `index`.
///
/// Original: `FUN_0829c01c` @ `0x0829c01c` (12 bytes; seven unconditional
/// direct `bl` call sites). The ARM `lsl #3` and `add` wrap at 32 bits; no
/// pointer or bounds check is present.
///
/// # Safety
///
/// `table` must point to readable [`OpaqueRecordTable`] storage. Its `entries`
/// field is returned with an index-derived byte offset, exactly as retailOS;
/// callers must ensure the resulting pointer is valid before dereferencing it.
#[cfg_attr(target_os = "none", link_section = ".text.opaque_record_table_entry_at")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_record_table_entry_at(
    table: *const OpaqueRecordTable,
    index: u32,
) -> *mut u8 {
    unsafe { (*table).entries.wrapping_add(index.wrapping_shl(3) as usize) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{opaque_record_table_entry_at, OpaqueRecordTable};

    #[test]
    fn returns_the_requested_eight_byte_record() {
        let mut records = [[0u8; 8]; 4];
        records[3][0] = 0xa5;
        let table = OpaqueRecordTable {
            prefix_words: [0x1111_1111, 0x2222_2222, 0x3333_3333],
            entries: records.as_mut_ptr().cast(),
        };

        unsafe {
            assert_eq!(opaque_record_table_entry_at(&table, 0), records[0].as_mut_ptr());
            let record = opaque_record_table_entry_at(&table, 3);
            assert_eq!(record, records[3].as_mut_ptr());
            assert_eq!(*record, 0xa5);
        }
    }

    #[test]
    fn preserves_the_table_and_applies_wrapping_shift() {
        let mut records = [[0u8; 8]; 1];
        let table = OpaqueRecordTable {
            prefix_words: [0x4444_4444, 0x5555_5555, 0x6666_6666],
            entries: records.as_mut_ptr().cast(),
        };
        let before = table;
        let shifted_index = u32::MAX.wrapping_shl(3);

        unsafe {
            assert_eq!(
                opaque_record_table_entry_at(&table, u32::MAX),
                table.entries.wrapping_add(shifted_index as usize),
            );
        }
        assert_eq!(table, before, "the accessor must not modify the table");
    }
}
