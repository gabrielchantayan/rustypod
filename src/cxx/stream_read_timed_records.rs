//! Read a block and append timed records — FUN_08282a90 @ 0x08282a90.
//!
//! True extent 208 bytes (200 code + 8 literal pool), next function 0x08282b60.
//! Two inbound plain BLs at 0x08282cf8/0x08282d80, zero predicated BLs.
//! Body: seven plain BLs, zero predicated BLs, one indirect BLX (slot +0x10).
//! Require an exact-length virtual read with mode 2; otherwise return 1 without
//! writing records. For each signed-positive record count, write buffer address,
//! stride, and base time + trunc(f64(f32(index*stride)/f32(byte_rate))*8*1000),
//! then move the record cursor back 12 bytes. Return 0 on success.
//! Deviations: host pointers widen structurally; target layout and wrapping
//! word arithmetic are retained. All floating operations use existing ADS ports.

//! LLVM inlines conversion/scaling helpers: match.py reports 168 instructions
//! versus the original 50; exact-read guard and backward record loop remain.
use crate::fp::{fp_dconv::__d2i, fp_dmul::__dmul, fp_fconv::{__i2f, __f2d},
    fp_fmuldiv::__fdiv, fp_scalb::__dscalb};

pub type BlockRead = unsafe extern "C" fn(*mut BlockSource, *mut u8, i32, u32) -> i32;

#[repr(C)]
pub struct BlockVtable {
    pub preceding: [usize; 4],
    pub read: BlockRead,
}

#[repr(C)]
pub struct BlockSource {
    pub vtable: *const BlockVtable,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimedRecord {
    pub address: u32,
    pub length: i32,
    pub time: i32,
}

#[repr(C)]
pub struct TimedBlockReader {
    pub header: u32,
    pub source: *mut BlockSource,
    pub unknown_08_10: [u32; 3],
    pub byte_rate: i32,
    pub unknown_18_20: [u32; 3],
    pub stride: i32,
    pub unknown_28: u32,
    pub cursor: *mut TimedRecord,
    pub base_time: i32,
}

/// # Safety
/// Reader/source/vtable must be valid and the read slot must accept this ABI.
/// For positive count, cursor and all preceding output records must be writable;
/// the final decremented cursor must remain within the same allocation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_read_timed_records(
    reader: *mut TimedBlockReader, buffer: *mut u8, length: i32, count: i32,
) -> u32 {
    let source = (*reader).source;
    if ((*(*source).vtable).read)(source, buffer, length, 2) != length {
        return 1;
    }
    let mut index = 0i32;
    while index < count {
        let cursor = (*reader).cursor;
        (*cursor).address = (buffer as usize as u32)
            .wrapping_add(index.wrapping_mul((*reader).stride) as u32);
        (*(*reader).cursor).length = (*reader).stride;
        let rate = __i2f((*reader).byte_rate);
        let offset = __i2f(index.wrapping_mul((*reader).stride));
        let seconds = __f2d(__fdiv(offset, rate));
        let time = __d2i(__dmul(__dscalb(seconds, 3), 0x408f_4000_0000_0000));
        (*(*reader).cursor).time = time.wrapping_add((*reader).base_time);
        (*reader).cursor = (*reader).cursor.sub(1);
        index += 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Source { base: BlockSource, result: i32, calls: u32 }
    unsafe extern "C" fn read(source: *mut BlockSource, _: *mut u8, _: i32, mode: u32) -> i32 {
        assert_eq!(mode, 2);
        let source = source as *mut Source;
        (*source).calls += 1;
        (*source).result
    }

    #[test]
    fn exact_read_signed_count_and_backward_record_order() {
        let table = BlockVtable { preceding: [0; 4], read };
        let mut source = Source { base: BlockSource { vtable: &table }, result: 21, calls: 0 };
        let sentinel = TimedRecord { address: 99, length: -99, time: -99 };
        let mut records = [sentinel; 5];
        let mut buffer = [0u8; 21];
        let mut reader = TimedBlockReader {
            header: 0, source: &mut source.base, unknown_08_10: [0; 3], byte_rate: 44100,
            unknown_18_20: [0; 3], stride: 7, unknown_28: 0,
            cursor: unsafe { records.as_mut_ptr().add(4) }, base_time: 123,
        };
        for result in [0, 20, 22, -1] {
            source.result = result;
            let cursor = reader.cursor;
            assert_eq!(unsafe { stream_read_timed_records(&mut reader, buffer.as_mut_ptr(), 21, 3) }, 1);
            assert_eq!(reader.cursor, cursor);
            assert_eq!(records, [sentinel; 5]);
        }
        source.result = 21;
        for count in [0, -1, i32::MIN] {
            assert_eq!(unsafe { stream_read_timed_records(&mut reader, buffer.as_mut_ptr(), 21, count) }, 0);
            assert_eq!(records, [sentinel; 5]);
        }
        assert_eq!(unsafe { stream_read_timed_records(&mut reader, buffer.as_mut_ptr(), 21, 3) }, 0);
        for index in 0..3 {
            let expected_time = (((index * 7) as f32 / 44100.0f32) as f64 * 8.0 * 1000.0) as i32 + 123;
            assert_eq!(records[4-index], TimedRecord {
                address: (buffer.as_ptr() as usize as u32).wrapping_add((index*7) as u32),
                length: 7, time: expected_time,
            });
        }
        assert_eq!(records[0..2], [sentinel; 2]);
        assert_eq!(reader.cursor, unsafe { records.as_mut_ptr().add(1) });
        assert_eq!(source.calls, 8);
    }

    #[test]
    fn signed_offsets_and_timestamp_addition_wrap() {
        let table = BlockVtable { preceding: [0; 4], read };
        let mut source = Source { base: BlockSource { vtable: &table }, result: 0, calls: 0 };
        let mut records = [TimedRecord { address: 0, length: 0, time: 0 }; 3];
        let mut reader = TimedBlockReader {
            header: 0, source: &mut source.base, unknown_08_10: [0; 3], byte_rate: 8,
            unknown_18_20: [0; 3], stride: -3, unknown_28: 0,
            cursor: unsafe { records.as_mut_ptr().add(2) }, base_time: i32::MIN,
        };
        assert_eq!(unsafe { stream_read_timed_records(&mut reader, core::ptr::null_mut(), 0, 2) }, 0);
        assert_eq!(records[2], TimedRecord { address: 0, length: -3, time: i32::MIN });
        assert_eq!(records[1], TimedRecord { address: u32::MAX-2, length: -3, time: i32::MIN.wrapping_sub(3000) });
    }
}
