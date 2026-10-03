//! Backward traversal of the UI's buffered UTF-16 text history.

use super::range_byte_lookup::{range_byte_lookup, RangeByteTable};

/// Host replacement for the table pointer stored at retailOS `0x089d01f8`.
/// Callers must install a valid descriptor before invoking the port on host.
#[cfg(not(target_os = "none"))]
pub static mut TEXT_HISTORY_BYTE_TABLE: *const RangeByteTable = core::ptr::null();

/// `text_history_previous` — original `FUN_08233208` @ `0x08233208`.
/// True extent: 56 bytes through `0x0823323f`, including the literal at
/// `0x0823323c`; the next function starts at `0x08233240`. Raw A32 words
/// contain one plain BL (to `range_byte_lookup` at `0x0829f1f4`) and zero
/// predicated BLs. Two inbound plain BLs occur at `0x081330f0` and
/// `0x08133150`, with zero predicated inbound BLs.
///
/// Subtracts two from the target-width cursor at history offset `+0x408`,
/// stores the cursor, then reads and outputs its UTF-16 code unit. Looks up
/// that unsigned code unit using the descriptor pointer at `0x089d01f8`
/// and outputs the mapped byte. No bounds, NUL, or surrogate checks.
///
/// Deliberate deviations: host builds use an explicitly installed table
/// pointer instead of the firmware global. Target behavior is unchanged.
///
/// # Safety
/// `history + 0x408` must be an aligned readable/writable u32 cursor, whose
/// value minus two designates a readable aligned u16. Both output pointers
/// must be writable and aligned for their types. The global table must meet
/// `range_byte_lookup`'s requirements. Aliasing is allowed; writes occur in
/// firmware order, with the table pointer loaded after the code-unit output.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn text_history_previous(
    history: *mut u8,
    code_unit: *mut u16,
    mapped_byte: *mut u8,
) {
    unsafe {
        let cursor_slot = history.add(0x408).cast::<u32>();
        let cursor = cursor_slot.read().wrapping_sub(2);
        cursor_slot.write(cursor);
        let character = (cursor as usize as *const u16).read();
        code_unit.write(character);
        #[cfg(target_os = "none")]
        let table = (0x089d_01f8usize as *const u32).read() as *const RangeByteTable;
        #[cfg(not(target_os = "none"))]
        let table = core::ptr::addr_of!(TEXT_HISTORY_BYTE_TABLE).read();
        mapped_byte.write(range_byte_lookup(table, character as i32));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn walks_backwards_without_treating_nul_or_surrogates_as_terminators() {
        let Some(slab) = try_map_u32_slab(hints::TEXT_HISTORY_PREVIOUS, 0x12000) else {
            assert!(note_missing_u32_fixture("ui/text_history_previous"));
            return;
        };
        unsafe {
            let history = slab;
            let characters = slab.add(0x800).cast::<u16>();
            let table = slab.add(0x900).cast::<RangeByteTable>();
            let data = slab.add(0x1000);
            table.write(RangeByteTable { first: 0, last: 0xfffe, data: data as usize as u32 });
            let values = [0, 0x41, 0xd800, 0xfffe, 0xffff];
            for (index, &value) in values.iter().enumerate() {
                characters.add(index).write(value);
            }
            for (key, byte) in [(0, 0x91), (0x41, 0x92), (0xd800, 0x93), (0xfffe, 0x94)] {
                data.add(key).write(byte);
            }
            let cursor = history.add(0x408).cast::<u32>();
            cursor.write(characters.add(values.len()) as usize as u32);
            TEXT_HISTORY_BYTE_TABLE = table;
            let mut character = 0xaaaa;
            let mut mapped = 0xaa;
            for (index, expected) in [0, 0x94, 0x93, 0x92, 0x91].into_iter().enumerate() {
                text_history_previous(history, &mut character, &mut mapped);
                let position = values.len() - index - 1;
                assert_eq!(character, values[position]);
                assert_eq!(mapped, expected);
                assert_eq!(cursor.read(), characters.add(position) as usize as u32);
            }
            // Output may overwrite the source halfword: the lookup still uses
            // the already-loaded code unit, and the byte output is written last.
            cursor.write(characters.add(2) as usize as u32);
            text_history_previous(history, characters.add(1), characters.add(1).cast::<u8>());
            assert_eq!(characters.add(1).read(), 0x92);
            assert_eq!(cursor.read(), characters.add(1) as usize as u32);
            TEXT_HISTORY_BYTE_TABLE = core::ptr::null();
        }
    }
}
