//! Byte-to-nibble-pair writer, `FUN_080779a0` @ 0x080779a0.
//!
//! True extent: 120 bytes through 0x08077a17 (116 instruction bytes plus
//! the table-pointer literal); the next PUSH begins at 0x08077a18.
//! Verified incoming calls: two plain BLs at 0x080eb9d4 and 0x080eba34,
//! zero predicated BLs. Body: zero direct BLs, one unconditional BLX r7.
//! For each input byte, emit table[high nibble], table[low nibble] in one
//! two-byte writer call. Zero writer result returns -1 immediately; any
//! nonzero result succeeds. A NULL context skips all reads and calls.
//! Success returns the input length shifted left one with u32 wrapping.
//! The table at 0x08977f8b is NOT ASCII in the supplied raw firmware:
//! 1d 01 a4 e3 21 8f 0d 04 42 00 00 50 b6 cf 0d 04.
//! Deliberate deviation: host builds relocate those exact table bytes;
//! firmware builds retain the original table address. No alphabet repair.

use core::ffi::c_void;
use super::write_nul_padding::WriteBytes;

#[cfg(not(target_os = "none"))]
static HOST_NIBBLE_TABLE: [u8; 16] = [
    0x1d, 0x01, 0xa4, 0xe3, 0x21, 0x8f, 0x0d, 0x04,
    0x42, 0x00, 0x00, 0x50, 0xb6, 0xcf, 0x0d, 0x04,
];

/// Encode bytes through the retail nibble table and supplied writer.
///
/// `source` must cover `length` readable bytes when context is non-NULL.
/// The writer must consume each stack-backed pair before returning and may
/// mutate subsequent source bytes. Its context and function must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn write_hex_bytes(
    writer: WriteBytes,
    context: *mut c_void,
    source: *const u8,
    length: u32,
) -> i32 {
    if !context.is_null() {
        #[cfg(target_os = "none")]
        let table = 0x0897_7f8busize as *const u8;
        #[cfg(not(target_os = "none"))]
        let table = HOST_NIBBLE_TABLE.as_ptr();
        let mut cursor = source;
        let end = source.wrapping_add(length as usize);
        while cursor != end {
            let high = unsafe { cursor.read_volatile() } >> 4;
            let low = unsafe { cursor.read_volatile() } & 15;
            let pair = unsafe { [table.add(high as usize).read(), table.add(low as usize).read()] };
            if unsafe { writer(context, pair.as_ptr(), 2) } == 0 {
                return -1;
            }
            cursor = cursor.wrapping_add(1);
        }
    }
    length.wrapping_shl(1) as i32
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    struct Sink {
        pairs: Vec<[u8; 2]>,
        fail_at: usize,
        result: u32,
        mutate: *mut u8,
    }

    unsafe extern "C" fn collect(context: *mut c_void, bytes: *const u8, length: u32) -> u32 {
        let sink = unsafe { &mut *context.cast::<Sink>() };
        assert_eq!(length, 2);
        sink.pairs.push(unsafe { [bytes.read(), bytes.add(1).read()] });
        if !sink.mutate.is_null() {
            unsafe { sink.mutate.write(0xf0); }
        }
        if sink.pairs.len() == sink.fail_at { 0 } else { sink.result }
    }

    fn sink() -> Sink {
        Sink { pairs: Vec::new(), fail_at: usize::MAX, result: u32::MAX, mutate: core::ptr::null_mut() }
    }

    #[test]
    fn all_byte_values_use_raw_table_in_high_low_order() {
        let source: [u8; 256] = core::array::from_fn(|i| i as u8);
        let mut sink = sink();
        assert_eq!(unsafe { write_hex_bytes(collect, (&mut sink as *mut Sink).cast(), source.as_ptr(), 256) }, 512);
        let reference = [0x1d, 0x01, 0xa4, 0xe3, 0x21, 0x8f, 0x0d, 0x04, 0x42, 0, 0, 0x50, 0xb6, 0xcf, 0x0d, 0x04];
        for (value, pair) in sink.pairs.iter().enumerate() {
            assert_eq!(*pair, [reference[value / 16], reference[value % 16]]);
        }
        assert_eq!(sink.pairs.len(), 256);
    }

    #[test]
    fn zero_context_and_empty_source_do_not_read_or_call_and_count_wraps() {
        for length in [0, 1, 0x4000_0000, 0x8000_0000, u32::MAX] {
            assert_eq!(unsafe { write_hex_bytes(collect, core::ptr::null_mut(), core::ptr::null(), length) }, length.wrapping_mul(2) as i32);
        }
        let mut sink = sink();
        assert_eq!(unsafe { write_hex_bytes(collect, (&mut sink as *mut Sink).cast(), core::ptr::null(), 0) }, 0);
        assert!(sink.pairs.is_empty());
    }

    #[test]
    fn failure_stops_at_first_rejected_pair() {
        for fail_at in 1..=3 {
            let mut sink = sink();
            sink.fail_at = fail_at;
            let source = [0x12, 0xab, 0xff];
            assert_eq!(unsafe { write_hex_bytes(collect, (&mut sink as *mut Sink).cast(), source.as_ptr(), 3) }, -1);
            assert_eq!(sink.pairs, [[0x01, 0xa4], [0x00, 0x50], [0x04, 0x04]][..fail_at]);
        }
    }

    #[test]
    fn callback_mutation_of_next_byte_is_observed() {
        let mut source = [0x12, 0x34];
        let mut sink = sink();
        sink.mutate = unsafe { source.as_mut_ptr().add(1) };
        assert_eq!(unsafe { write_hex_bytes(collect, (&mut sink as *mut Sink).cast(), source.as_ptr(), 2) }, 4);
        assert_eq!(sink.pairs, [[0x01, 0xa4], [0x04, 0x1d]]);
    }
}
