//! Packed-record field deserialization — SQLite turns one serial-typed
//! payload segment into a transient `Mem` for record comparison.
//!
//! - `vdbe_serial_get` — original: `FUN_0838cc1c` @ 0x0838cc1c (484
//!   bytes, 0x0838cc1c..0x0838ce00). Upstream SQLite 3.5.9's
//!   `sqlite3VdbeSerialGet` (vdbeaux.c): `u32 sqlite3VdbeSerialGet(const
//!   u8 *buf, u32 serial_type, Mem *p_mem)`. functions.csv's 484-byte
//!   extent is exact: the 121st and final instruction is the return at
//!   0x0838cdfc; the next four bytes, 0x0838ce00 = `0x00000102`, are the
//!   text-flags literal pool word, and the next function starts with
//!   `stmdb sp!,{r4,r5,r6,r7,r8,lr}` at 0x0838ce04. Binary-verified in
//!   osos.dec.
//!
//! ### Algorithm
//!
//! The jump table handles NULL and reserved serial types 0/10/11, the
//! signed big-endian integer widths 1/2/3/4/6/8 (types 1..=6), an
//! IEEE-754 binary64 (type 7), and the zero/one integer constants
//! (types 8/9). A NaN real becomes NULL, precisely as upstream's
//! `sqlite3IsNaN` branch dictates. Types at least 12 point `Mem.z` at
//! `buf`, stamp `Mem.n = (serial_type - 12) >> 1`, clear `xDel`, and
//! select text (odd, `0x102`) or blob (even, `0x110`) ephemeral flags.
//! The return is the payload bytes consumed.
//!
//! ### Deviations
//!
//! `p_mem` remains a raw original-layout 0x28-byte `Mem` rather than the
//! typed host `Mem`: its 32-bit `z` and `xDel` fields must retain their
//! target offsets. On a 64-bit test host their pointer words are therefore
//! the low 32 bits, while on the ARM target they are the complete pointers.
//! Rust's `f64::is_nan` is the same self-inequality predicate as the
//! unported `sqlite3IsNaN` @ 0x0837cb44 that the firmware calls.

use super::value_new::{MEM_FLAGS_OFFSET, MEM_NULL};

/// Original `Mem.u` offset.
pub const MEM_U_OFFSET: usize = 0x00;
/// Original `Mem.r` offset.
pub const MEM_R_OFFSET: usize = 0x08;
/// Original `Mem.z` offset.
pub const MEM_Z_OFFSET: usize = 0x14;
/// Original `Mem.n` offset.
pub const MEM_N_OFFSET: usize = 0x18;
/// Original `Mem.xDel` offset.
pub const MEM_X_DEL_OFFSET: usize = 0x20;

/// `MEM_Int`, stamped for serial types 1..=6 and 8/9.
pub const MEM_INT: u16 = 0x0004;
/// `MEM_Real`, stamped for a non-NaN serial type 7.
pub const MEM_REAL: u16 = 0x0008;
/// `MEM_Str | MEM_Ephem`, the odd serial-type tail's flags.
pub const MEM_TEXT_EPHEM: u16 = 0x0102;
/// `MEM_Blob | MEM_Ephem`, the even serial-type tail's flags.
pub const MEM_BLOB_EPHEM: u16 = 0x0110;

#[inline(always)]
unsafe fn store_u16(p_mem: *mut u8, offset: usize, value: u16) {
    (p_mem.add(offset) as *mut u16).write(value);
}

#[inline(always)]
unsafe fn store_u32(p_mem: *mut u8, offset: usize, value: u32) {
    (p_mem.add(offset) as *mut u32).write(value);
}

#[inline(always)]
unsafe fn store_u64(p_mem: *mut u8, offset: usize, value: u64) {
    (p_mem.add(offset) as *mut u64).write(value);
}

/// vdbe_serial_get — original: `FUN_0838cc1c` @ 0x0838cc1c (484 bytes).
///
/// `sqlite3VdbeSerialGet`: deserialize the serial-typed record field at
/// `buf` into the raw 0x28-byte `Mem` at `p_mem`, returning its payload
/// length. See the module header for the original jump table and host
/// raw-layout deviation.
///
/// # Safety
/// `p_mem` must point to an aligned writable 0x28-byte target-layout
/// `Mem`. `buf` must provide the byte width implied by `serial_type` for
/// types 1 through 7; types at least 12 need only be a valid pointer for
/// the resulting `Mem.z` alias.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_serial_get(
    buf: *const u8,
    serial_type: u32,
    p_mem: *mut u8,
) -> u32 {
    match serial_type {
        0 | 10 | 11 => {
            store_u16(p_mem, MEM_FLAGS_OFFSET, MEM_NULL);
            0
        }
        1 => {
            store_u64(p_mem, MEM_U_OFFSET, (*buf as i8 as i64) as u64);
            store_u16(p_mem, MEM_FLAGS_OFFSET, MEM_INT);
            1
        }
        2 => {
            let value = i16::from_be_bytes([*buf, *buf.add(1)]) as i64;
            store_u64(p_mem, MEM_U_OFFSET, value as u64);
            store_u16(p_mem, MEM_FLAGS_OFFSET, MEM_INT);
            2
        }
        3 => {
            let value = ((*buf as i8 as i64) << 16)
                | ((*buf.add(1) as i64) << 8)
                | *buf.add(2) as i64;
            store_u64(p_mem, MEM_U_OFFSET, value as u64);
            store_u16(p_mem, MEM_FLAGS_OFFSET, MEM_INT);
            3
        }
        4 => {
            let value = i32::from_be_bytes([*buf, *buf.add(1), *buf.add(2), *buf.add(3)]) as i64;
            store_u64(p_mem, MEM_U_OFFSET, value as u64);
            store_u16(p_mem, MEM_FLAGS_OFFSET, MEM_INT);
            4
        }
        5 => {
            let high = i16::from_be_bytes([*buf, *buf.add(1)]) as i64;
            let low = u32::from_be_bytes([*buf.add(2), *buf.add(3), *buf.add(4), *buf.add(5)]);
            store_u64(p_mem, MEM_U_OFFSET, ((high << 32) | low as i64) as u64);
            store_u16(p_mem, MEM_FLAGS_OFFSET, MEM_INT);
            6
        }
        6 => {
            let value = i64::from_be_bytes([
                *buf,
                *buf.add(1),
                *buf.add(2),
                *buf.add(3),
                *buf.add(4),
                *buf.add(5),
                *buf.add(6),
                *buf.add(7),
            ]);
            store_u64(p_mem, MEM_U_OFFSET, value as u64);
            store_u16(p_mem, MEM_FLAGS_OFFSET, MEM_INT);
            8
        }
        7 => {
            let value = f64::from_bits(u64::from_be_bytes([
                *buf,
                *buf.add(1),
                *buf.add(2),
                *buf.add(3),
                *buf.add(4),
                *buf.add(5),
                *buf.add(6),
                *buf.add(7),
            ]));
            (p_mem.add(MEM_R_OFFSET) as *mut f64).write(value);
            store_u16(
                p_mem,
                MEM_FLAGS_OFFSET,
                if value.is_nan() { MEM_NULL } else { MEM_REAL },
            );
            8
        }
        8 | 9 => {
            store_u64(p_mem, MEM_U_OFFSET, (serial_type - 8) as u64);
            store_u16(p_mem, MEM_FLAGS_OFFSET, MEM_INT);
            0
        }
        _ => {
            let len = serial_type.wrapping_sub(12) >> 1;
            store_u32(p_mem, MEM_Z_OFFSET, buf as usize as u32);
            store_u32(p_mem, MEM_N_OFFSET, len);
            store_u32(p_mem, MEM_X_DEL_OFFSET, 0);
            store_u16(
                p_mem,
                MEM_FLAGS_OFFSET,
                if serial_type & 1 != 0 {
                    MEM_TEXT_EPHEM
                } else {
                    MEM_BLOB_EPHEM
                },
            );
            len
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::super::value_new::MEM_SIZE;
    use super::*;

    #[repr(align(8))]
    struct MemBlock([u8; MEM_SIZE as usize]);

    unsafe fn put_u16(mem: &mut [u8], offset: usize, value: u16) {
        mem[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
    }

    unsafe fn put_u32(mem: &mut [u8], offset: usize, value: u32) {
        mem[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }

    unsafe fn put_u64(mem: &mut [u8], offset: usize, value: u64) {
        mem[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
    }

    /// Independent model of the jump table: it mutates only the raw
    /// original-layout fields each retail case writes.
    unsafe fn reference_serial_get(
        buf: *const u8,
        serial_type: u32,
        mem: &mut [u8; MEM_SIZE as usize],
    ) -> u32 {
        match serial_type {
            0 | 10 | 11 => {
                put_u16(mem, MEM_FLAGS_OFFSET, MEM_NULL);
                0
            }
            1..=6 => {
                let len = [0usize, 1, 2, 3, 4, 6, 8][serial_type as usize];
                let mut value = *buf as i8 as i64;
                for index in 1..len {
                    value = (value << 8) | *buf.add(index) as i64;
                }
                put_u64(mem, MEM_U_OFFSET, value as u64);
                put_u16(mem, MEM_FLAGS_OFFSET, MEM_INT);
                len as u32
            }
            7 => {
                let mut bits = 0u64;
                for index in 0..8 {
                    bits = (bits << 8) | *buf.add(index) as u64;
                }
                let value = f64::from_bits(bits);
                put_u64(mem, MEM_R_OFFSET, value.to_bits());
                put_u16(
                    mem,
                    MEM_FLAGS_OFFSET,
                    if value.is_nan() { MEM_NULL } else { MEM_REAL },
                );
                8
            }
            8 | 9 => {
                put_u64(mem, MEM_U_OFFSET, (serial_type - 8) as u64);
                put_u16(mem, MEM_FLAGS_OFFSET, MEM_INT);
                0
            }
            _ => {
                let len = serial_type.wrapping_sub(12) >> 1;
                put_u32(mem, MEM_Z_OFFSET, buf as usize as u32);
                put_u32(mem, MEM_N_OFFSET, len);
                put_u32(mem, MEM_X_DEL_OFFSET, 0);
                put_u16(
                    mem,
                    MEM_FLAGS_OFFSET,
                    if serial_type & 1 != 0 {
                        MEM_TEXT_EPHEM
                    } else {
                        MEM_BLOB_EPHEM
                    },
                );
                len
            }
        }
    }

    unsafe fn decode_against_reference(buf: *const u8, serial_type: u32) -> MemBlock {
        let mut actual = MemBlock([0xa5; MEM_SIZE as usize]);
        let mut expected = [0xa5; MEM_SIZE as usize];
        let expected_len = reference_serial_get(buf, serial_type, &mut expected);
        let actual_len = vdbe_serial_get(buf, serial_type, actual.0.as_mut_ptr());
        assert_eq!(actual_len, expected_len, "serial type {serial_type}");
        assert_eq!(actual.0, expected, "serial type {serial_type}");
        actual
    }

    #[test]
    fn every_fixed_serial_type_and_the_string_blob_boundary_match_the_model() {
        let payload = [0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        unsafe {
            for serial_type in 0..=12 {
                decode_against_reference(payload.as_ptr(), serial_type);
            }
        }
    }

    #[test]
    fn every_integer_width_sign_extends_its_big_endian_high_bit() {
        let cases: &[(u32, &[u8], i64)] = &[
            (1, &[0x80], -128),
            (2, &[0x80, 0x00], -32_768),
            (3, &[0x80, 0x00, 0x00], -8_388_608),
            (4, &[0x80, 0x00, 0x00, 0x00], -2_147_483_648),
            (5, &[0x80, 0x00, 0x00, 0x00, 0x00, 0x00], -140_737_488_355_328),
            (6, &[0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], i64::MIN),
        ];
        unsafe {
            for &(serial_type, bytes, expected) in cases {
                let mem = decode_against_reference(bytes.as_ptr(), serial_type);
                let value = (mem.0.as_ptr().add(MEM_U_OFFSET) as *const u64).read() as i64;
                assert_eq!(value, expected, "serial type {serial_type}");
                assert_eq!(
                    (mem.0.as_ptr().add(MEM_FLAGS_OFFSET) as *const u16).read(),
                    MEM_INT
                );
            }
        }
    }

    #[test]
    fn real_preserves_its_ieee_bits_and_nan_becomes_null() {
        let finite = 0xc005_bf0a_8b14_5769u64.to_be_bytes();
        let nan = 0x7ff8_0000_0000_0001u64.to_be_bytes();
        unsafe {
            let finite_mem = decode_against_reference(finite.as_ptr(), 7);
            assert_eq!(
                (finite_mem.0.as_ptr().add(MEM_R_OFFSET) as *const f64).read().to_bits(),
                u64::from_be_bytes(finite),
            );
            assert_eq!(
                (finite_mem.0.as_ptr().add(MEM_FLAGS_OFFSET) as *const u16).read(),
                MEM_REAL
            );

            let nan_mem = decode_against_reference(nan.as_ptr(), 7);
            assert_eq!(
                (nan_mem.0.as_ptr().add(MEM_R_OFFSET) as *const f64).read().to_bits(),
                u64::from_be_bytes(nan),
            );
            assert_eq!(
                (nan_mem.0.as_ptr().add(MEM_FLAGS_OFFSET) as *const u16).read(),
                MEM_NULL
            );
        }
    }

    #[test]
    fn string_and_blob_tails_keep_the_caller_buffer_pointer_and_length() {
        let payload = *b"prefix-data";
        unsafe {
            for &(serial_type, start, len, flags) in &[
                (12, 0usize, 0u32, MEM_BLOB_EPHEM),
                (13, 1, 0, MEM_TEXT_EPHEM),
                (20, 2, 4, MEM_BLOB_EPHEM),
                (21, 3, 4, MEM_TEXT_EPHEM),
            ] {
                let buf = payload.as_ptr().add(start);
                let mem = decode_against_reference(buf, serial_type);
                assert_eq!(
                    (mem.0.as_ptr().add(MEM_Z_OFFSET) as *const u32).read(),
                    buf as usize as u32,
                    "serial type {serial_type} points at its caller payload"
                );
                assert_eq!(
                    (mem.0.as_ptr().add(MEM_N_OFFSET) as *const u32).read(),
                    len
                );
                assert_eq!(
                    (mem.0.as_ptr().add(MEM_X_DEL_OFFSET) as *const u32).read(),
                    0
                );
                assert_eq!(
                    (mem.0.as_ptr().add(MEM_FLAGS_OFFSET) as *const u16).read(),
                    flags
                );
            }
        }
    }
}
