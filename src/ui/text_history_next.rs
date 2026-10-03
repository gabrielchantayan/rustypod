//! Forward traversal and ligature expansion of buffered UI text history.

use crate::cxx::string_object::utf8_next_codepoint;
use super::range_byte_lookup::{range_byte_lookup, RangeByteTable};

/// Host replacement for the descriptor pointer at retailOS `0x089d01f8`.
/// Separate from the backward port's fixture to permit parallel host tests.
#[cfg(not(target_os = "none"))]
pub static mut TEXT_HISTORY_NEXT_BYTE_TABLE: *const RangeByteTable = core::ptr::null();

/// `text_history_next` — original `FUN_08233128` @ `0x08233128`.
/// True extent: 224 bytes through `0x08233207` (208 instruction bytes and
/// 16 literal bytes); the next independently entered function is 0x08233208.
/// Raw words contain two plain BLs (UTF-8 decoder 0x08276214 and range lookup
/// 0x0829f1f4), zero predicated BLs.
///
/// If the halfword after the history cursor is zero, decode from the u32
/// source pointer at +4. Write the decoded value to the output, then append
/// either that halfword and zero, or uppercase OE for U+0152/U+0153 and AE
/// for U+00C6/U+00E6 followed by zero. Advance the u32 cursor at +0x408 by
/// two, output its halfword, and map it through the global range table.
/// Buffered nonzero halfwords bypass decoding. NUL still advances both
/// cursors; there are no bounds or surrogate checks.
///
/// Deliberate deviations: host decoding uses a native-width local pointer
/// and writes it back as u32; host table access uses an installed descriptor
/// instead of the firmware global. Target layout and behavior are unchanged.
///
/// # Safety
/// History must contain aligned u32 source/cursor slots at +4/+0x408.
/// The source must satisfy the decoder's requirements; the cursor must
/// permit the halfword accesses through +6. Outputs and the global table
/// must be valid. Writes retain firmware order, including the initial
/// decoded output write before reloading the history cursor.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn text_history_next(
    history: *mut u8,
    code_unit: *mut u16,
    mapped_byte: *mut u8,
) {
    unsafe {
        let cursor_slot = history.add(0x408).cast::<u32>();
        let cursor = cursor_slot.read() as usize as *mut u16;
        if cursor.add(1).read() == 0 {
            let source_slot = history.add(4).cast::<u32>();
            #[cfg(target_os = "none")]
            let decoded = utf8_next_codepoint(source_slot.cast::<*const u8>());
            #[cfg(not(target_os = "none"))]
            let decoded = {
                let mut source = source_slot.read() as usize as *const u8;
                let value = utf8_next_codepoint(&mut source);
                source_slot.write(source as usize as u32);
                value
            };
            code_unit.write(decoded as u16);
            let expansion = match decoded {
                0x152 | 0x153 => Some([b'O', b'E']),
                0xc6 | 0xe6 => Some([b'A', b'E']),
                _ => None,
            };
            if let Some(pair) = expansion {
                (cursor_slot.read() as usize as *mut u16).add(1).write(pair[0] as u16);
                (cursor_slot.read() as usize as *mut u16).add(2).write(pair[1] as u16);
                (cursor_slot.read() as usize as *mut u16).add(3).write(0);
            } else {
                (cursor_slot.read() as usize as *mut u16).add(1).write(decoded as u16);
                (cursor_slot.read() as usize as *mut u16).add(2).write(0);
            }
        }
        let next = cursor_slot.read().wrapping_add(2);
        cursor_slot.write(next);
        let character = (next as usize as *const u16).read();
        code_unit.write(character);
        #[cfg(target_os = "none")]
        let table = (0x089d_01f8usize as *const u32).read() as *const RangeByteTable;
        #[cfg(not(target_os = "none"))]
        let table = core::ptr::addr_of!(TEXT_HISTORY_NEXT_BYTE_TABLE).read();
        mapped_byte.write(range_byte_lookup(table, character as i32));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn expands_ligatures_and_preserves_buffered_and_decoder_edges() {
        let Some(slab) = try_map_u32_slab(hints::TEXT_HISTORY_NEXT, 0x12000) else {
            assert!(note_missing_u32_fixture("ui/text_history_next"));
            return;
        };
        unsafe {
            let history = slab;
            let buffer = slab.add(0x800).cast::<u16>();
            let source = slab.add(0x900);
            let table = slab.add(0xa00).cast::<RangeByteTable>();
            let data = slab.add(0x1000);
            table.write(RangeByteTable { first: 0, last: 0xfffe, data: data as usize as u32 });
            for (key, value) in [(0, 0x90), (0x41, 0x91), (0x45, 0x92), (0x4f, 0x93), (0x80, 0x94), (0x154, 0x95), (0xd800, 0x96)] {
                data.add(key).write(value);
            }
            TEXT_HISTORY_NEXT_BYTE_TABLE = table;
            let source_slot = history.add(4).cast::<u32>();
            let cursor_slot = history.add(0x408).cast::<u32>();
            for (input, expected, mapped, advance) in [
                (&b"\xc5\x92\0"[..], &b"OE"[..], &b"\x93\x92"[..], 2),
                (&b"\xc5\x93\0"[..], &b"OE"[..], &b"\x93\x92"[..], 2),
                (&b"\xc3\x86\0"[..], &b"AE"[..], &b"\x91\x92"[..], 2),
                (&b"\xc3\xa6\0"[..], &b"AE"[..], &b"\x91\x92"[..], 2),
            ] {
                core::ptr::copy_nonoverlapping(input.as_ptr(), source, input.len());
                buffer.write(0xaaaa);
                buffer.add(1).write(0);
                cursor_slot.write(buffer as usize as u32);
                source_slot.write(source as usize as u32);
                for index in 0..2 {
                    let mut character = 0;
                    let mut byte = 0;
                    text_history_next(history, &mut character, &mut byte);
                    assert_eq!(character, expected[index] as u16);
                    assert_eq!(byte, mapped[index]);
                    assert_eq!(source_slot.read(), source.add(advance) as usize as u32);
                    assert_eq!(cursor_slot.read(), buffer.add(index + 1) as usize as u32);
                }
                assert_eq!(buffer.add(3).read(), 0);
            }
            for (input, expected, mapped, advance) in [
                (&b"A\0\0\0"[..], 0x41, 0x91, 1),
                (&b"\xc2\x80\0\0"[..], 0x80, 0x94, 2),
                (&b"\xc5\x94\0\0"[..], 0x154, 0x95, 2),
                (&b"\xed\xa0\x80\0"[..], 0xd800, 0x96, 3),
                (&b"\xef\xbf\xbf\0"[..], 0xffff, 0, 3),
                (&b"\xf0\x90\x80\0"[..], 0, 0x90, 3),
                (&b"\0\0\0\0"[..], 0, 0x90, 1),
            ] {
                core::ptr::copy_nonoverlapping(input.as_ptr(), source, input.len());
                buffer.add(1).write(0);
                cursor_slot.write(buffer as usize as u32);
                source_slot.write(source as usize as u32);
                let mut character = 0xaaaa;
                let mut byte = 0xaa;
                text_history_next(history, &mut character, &mut byte);
                assert_eq!((character, byte), (expected, mapped));
                assert_eq!(buffer.add(1).read(), expected);
                assert_eq!(buffer.add(2).read(), 0);
                assert_eq!(source_slot.read(), source.add(advance) as usize as u32);
                assert_eq!(cursor_slot.read(), buffer.add(1) as usize as u32);
            }
            // Buffered values bypass even an invalid source pointer. Aliased
            // outputs still map the loaded character, then overwrite its byte.
            buffer.add(1).write(0x4f);
            cursor_slot.write(buffer as usize as u32);
            source_slot.write(0);
            text_history_next(history, buffer.add(1), buffer.add(1).cast::<u8>());
            assert_eq!(buffer.add(1).read(), 0x93);
            assert_eq!(source_slot.read(), 0);
            TEXT_HISTORY_NEXT_BYTE_TABLE = core::ptr::null();
        }
    }
}
