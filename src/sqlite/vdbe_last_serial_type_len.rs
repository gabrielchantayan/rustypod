//! The last-record-header serial-type length helper.
//!
//! `vdbe_last_serial_type_len` — original: `FUN_0838b570` @ 0x0838b570
//! (84 bytes, 0x0838b570..0x0838b5c4). Raw ARM words establish three
//! unconditional `bl` instructions and no predicated `bl`: two calls to
//! `get_varint` @ 0x0837ac30 and one to `vdbe_serial_type_len` @ 0x0838cfe8.
//!
//! It decodes the record-header size at `record[0]` (the one-byte varint path
//! is inlined), addresses the byte immediately before `record + header_size`,
//! decodes that byte as a serial-type varint when its continuation bit is set,
//! and returns the serial type's payload length.
//!
//! Deliberate deviation: the firmware's `get_varint` out-parameter is a u32;
//! the established Rust export uses a u64 seam slot. This helper truncates the
//! decoded value to u32 at each call site, matching the original `ldr` and the
//! callee's single-word stores.

use super::{get_varint::get_varint, vdbe_serial_type_len::vdbe_serial_type_len};

#[inline(always)]
unsafe fn read_varint32_fast(p: *const u8) -> u32 {
    let first = *p;
    if first < 0x80 {
        first as u32
    } else {
        let mut value = 0u64;
        get_varint(p, &mut value);
        value as u32
    }
}

/// vdbe_last_serial_type_len — original: `FUN_0838b570` @ 0x0838b570 (84
/// bytes; three unconditional `bl` instructions, no predicated `bl`).
///
/// Returns the payload length represented by the serial type in the final byte
/// of the record header selected by its leading varint length.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_last_serial_type_len(record: *const u8) -> u32 {
    let header_size = read_varint32_fast(record);
    let serial_type = read_varint32_fast(record.add(header_size as usize - 1));
    vdbe_serial_type_len(serial_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_byte_header_size_and_serial_type_use_fixed_size_table() {
        let record = [2u8, 5];
        assert_eq!(unsafe { vdbe_last_serial_type_len(record.as_ptr()) }, 6);
    }

    #[test]
    fn one_byte_header_size_and_text_serial_type_use_tail_formula() {
        let record = [2u8, 23];
        assert_eq!(unsafe { vdbe_last_serial_type_len(record.as_ptr()) }, 5);
    }

    #[test]
    fn multi_byte_header_size_uses_get_varint_result_as_offset() {
        let mut record = [0u8; 131];
        record[0] = 0x81;
        record[1] = 0x02;
        record[129] = 6;
        assert_eq!(unsafe { vdbe_last_serial_type_len(record.as_ptr()) }, 8);
    }

    #[test]
    fn high_bit_final_byte_uses_get_varint_for_serial_type() {
        let mut record = [0u8; 131];
        record[0] = 0x81;
        record[1] = 0x02;
        record[129] = 0x81;
        record[130] = 0x0a;
        assert_eq!(unsafe { vdbe_last_serial_type_len(record.as_ptr()) }, 63);
    }
}
