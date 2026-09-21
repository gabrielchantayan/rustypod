//! Decoder range-segment collection — original: `FUN_082e2594` @ `0x082e2594`.
//!
//! Raw `osos.dec` establishes the exact 220-byte extent
//! `0x082e2594..0x082e2670`; the literal word at `0x082e2670` is followed by
//! the next independently linked function's `push {r4-r10,lr}`. The body has
//! three plain `bl` calls (`0x082e1378`, `0x082e1d98`, and `realloc` @
//! `0x0802edec`) and one predicated `blne` call (`free` @ `0x0802edc8`).
//!
//! It converts the decoder's bit count at `state+0x1c` into a ceiling count
//! of units of `1 << (shift_table[index] + 9)`, then repeatedly asks the
//! decoder for the next contiguous range. Each nonempty range is appended as
//! `{start, length}`; a zero pair terminates the returned allocation. Failed
//! decoding or growth frees the partial list and returns NULL.
//!
//! Deliberate deviations: the two decoder callees are still unported, so ARM
//! builds invoke their verified addresses while host tests install ABI seams.
//! The shift-table literal is represented by a replaceable host pointer; ARM
//! builds read its literal address `0x000001ce` directly. Allocation and
//! release remain direct calls to the ported retail `realloc` and `free`.
#[cfg(target_os = "none")]
use crate::runtime::malloc_rt::{free, realloc};

use core::ptr;

const SHIFT_TABLE_ADDRESS: usize = 0x0000_01ce;
const INITIAL_POSITION_ADDRESS: usize = 0x082e_1378;
const NEXT_RANGE_ADDRESS: usize = 0x082e_1d98;
const STATE_BIT_COUNT_WORD: usize = 0x1c / 4;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecoderRangeSegment {
    pub start: u32,
    pub length: u32,
}

pub type DecoderInitialPosition = unsafe extern "C" fn(u32, *mut u32) -> u32;
pub type DecoderNextRange = unsafe extern "C" fn(u32, u32, *mut u32, u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_decoder_initial_position(index: u32, state: *mut u32) -> u32 {
    unsafe { core::mem::transmute::<usize, DecoderInitialPosition>(INITIAL_POSITION_ADDRESS)(index, state) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_decoder_next_range(index: u32, start: u32, next_start: *mut u32, units: u32) -> u32 {
    unsafe { core::mem::transmute::<usize, DecoderNextRange>(NEXT_RANGE_ADDRESS)(index, start, next_start, units) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_decoder_initial_position(_index: u32, _state: *mut u32) -> u32 {
    panic!("decoder_range_segments requires decoder helper 0x082e1378")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_decoder_next_range(
    _index: u32,
    _start: u32,
    _next_start: *mut u32,
    _units: u32,
) -> u32 {
    panic!("decoder_range_segments requires decoder helper 0x082e1d98")
}

#[cfg(target_os = "none")]
pub static mut DECODER_INITIAL_POSITION: DecoderInitialPosition = retail_decoder_initial_position;
#[cfg(not(target_os = "none"))]
pub static mut DECODER_INITIAL_POSITION: DecoderInitialPosition = missing_decoder_initial_position;
#[cfg(target_os = "none")]
pub static mut DECODER_NEXT_RANGE: DecoderNextRange = retail_decoder_next_range;
#[cfg(not(target_os = "none"))]
pub static mut DECODER_NEXT_RANGE: DecoderNextRange = missing_decoder_next_range;
#[cfg(not(target_os = "none"))]
pub static mut DECODER_SHIFT_TABLE: *const u16 = ptr::null();

#[cfg(not(target_os = "none"))]
pub type DecoderRangeRealloc = unsafe extern "C" fn(*mut u8, usize) -> *mut u8;
#[cfg(not(target_os = "none"))]
pub type DecoderRangeFree = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_decoder_range_realloc(_ptr: *mut u8, _size: usize) -> *mut u8 {
    panic!("decoder_range_segments requires retail realloc")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_decoder_range_free(_ptr: *mut u8) {
    panic!("decoder_range_segments requires retail free")
}
#[cfg(not(target_os = "none"))]
pub static mut DECODER_RANGE_REALLOC: DecoderRangeRealloc = missing_decoder_range_realloc;
#[cfg(not(target_os = "none"))]
pub static mut DECODER_RANGE_FREE: DecoderRangeFree = missing_decoder_range_free;

#[inline(always)]
unsafe fn range_realloc(ptr: *mut u8, size: usize) -> *mut u8 {
    #[cfg(target_os = "none")]
    { unsafe { realloc(ptr, size) } }
    #[cfg(not(target_os = "none"))]
    { unsafe { ptr::read_volatile(ptr::addr_of!(DECODER_RANGE_REALLOC))(ptr, size) } }
}

#[inline(always)]
unsafe fn range_free(ptr: *mut u8) {
    #[cfg(target_os = "none")]
    { unsafe { free(ptr) } }
    #[cfg(not(target_os = "none"))]
    { unsafe { ptr::read_volatile(ptr::addr_of!(DECODER_RANGE_FREE))(ptr) } }
}

#[inline(always)]
unsafe fn shift_for_index(index: u32) -> u16 {
    #[cfg(target_os = "none")]
    {
        unsafe { (SHIFT_TABLE_ADDRESS as *const u16).add(index as usize).read() }
    }
    #[cfg(not(target_os = "none"))]
    {
        unsafe { ptr::read_volatile(ptr::addr_of!(DECODER_SHIFT_TABLE)).add(index as usize).read() }
    }
}

#[inline(always)]
fn decoder_initial_position() -> DecoderInitialPosition {
    unsafe { ptr::read_volatile(ptr::addr_of!(DECODER_INITIAL_POSITION)) }
}

#[inline(always)]
fn decoder_next_range() -> DecoderNextRange {
    unsafe { ptr::read_volatile(ptr::addr_of!(DECODER_NEXT_RANGE)) }
}

/// Builds a NULL-terminated array of contiguous decoder ranges.
///
/// `state` must be a valid decoder object with a readable target-width word at
/// `+0x1c`. `index` must select a valid shift-table entry and satisfy both
/// unported decoder helper contracts. The returned storage is retail heap
/// storage and must be released with `free`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn decoder_range_segments(index: u32, state: *mut u32) -> *mut DecoderRangeSegment {
    let shift = unsafe { shift_for_index(index) }.wrapping_add(9) as u32;
    let bits = unsafe { state.add(STATE_BIT_COUNT_WORD).read() };
    let mask = 1u32.wrapping_shl(shift).wrapping_sub(1);
    let mut remaining = (bits >> shift) + u32::from(bits & mask != 0);
    let mut start = unsafe { decoder_initial_position()(index, state) };
    let mut count = 0usize;
    let mut segments: *mut DecoderRangeSegment = ptr::null_mut();

    while remaining != 0 {
        let mut next_start = 0;
        let length = unsafe { decoder_next_range()(index, start, &mut next_start, remaining) };
        if length == 0 {
            if !segments.is_null() {
                unsafe { range_free(segments.cast()) };
            }
            return ptr::null_mut();
        }
        let grown = unsafe { range_realloc(segments.cast(), (count + 1) * core::mem::size_of::<DecoderRangeSegment>()) }
            as *mut DecoderRangeSegment;
        if grown.is_null() {
            return ptr::null_mut();
        }
        unsafe { grown.add(count).write(DecoderRangeSegment { start, length }) };
        segments = grown;
        count += 1;
        remaining = remaining.wrapping_sub(length);
        start = next_start;
    }

    let grown = unsafe { range_realloc(segments.cast(), (count + 1) * core::mem::size_of::<DecoderRangeSegment>()) }
        as *mut DecoderRangeSegment;
    if grown.is_null() {
        return ptr::null_mut();
    }
    unsafe { grown.add(count).write(DecoderRangeSegment { start: 0, length: 0 }) };
    grown
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut TABLE: [u16; 2] = [0; 2];
    static mut RANGES: [(u32, u32); 3] = [(0, 0); 3];
    static mut RANGE_INDEX: usize = 0;
    static mut STORAGE: [DecoderRangeSegment; 3] = [DecoderRangeSegment { start: 0, length: 0 }; 3];
    static mut FREE_COUNT: usize = 0;

    unsafe extern "C" fn reallocate(_ptr: *mut u8, _size: usize) -> *mut u8 {
        unsafe { STORAGE.as_mut_ptr().cast() }
    }
    unsafe extern "C" fn release(_ptr: *mut u8) {
        unsafe { FREE_COUNT += 1 };
    }

    unsafe extern "C" fn initial_position(_index: u32, _state: *mut u32) -> u32 { 100 }
    unsafe extern "C" fn next_range(_index: u32, _start: u32, next: *mut u32, _units: u32) -> u32 {
        unsafe {
            let (length, next_start) = RANGES[RANGE_INDEX];
            RANGE_INDEX += 1;
            next.write(next_start);
            length
        }
    }

    struct Fixture {
        initial: DecoderInitialPosition,
        next: DecoderNextRange,
        table: *const u16,
        realloc: DecoderRangeRealloc,
        free: DecoderRangeFree,
    }

    impl Fixture {
        fn install(ranges: &[(u32, u32)]) -> Self {
            unsafe {
                TABLE = [0, 0];
                RANGES = [(0, 0); 3];
                RANGES[..ranges.len()].copy_from_slice(ranges);
                RANGE_INDEX = 0;
                FREE_COUNT = 0;
                STORAGE = [DecoderRangeSegment { start: 0, length: 0 }; 3];
                let fixture = Self {
                    initial: ptr::read_volatile(ptr::addr_of!(DECODER_INITIAL_POSITION)),
                    next: ptr::read_volatile(ptr::addr_of!(DECODER_NEXT_RANGE)),
                    table: ptr::read_volatile(ptr::addr_of!(DECODER_SHIFT_TABLE)),
                    realloc: ptr::read_volatile(ptr::addr_of!(DECODER_RANGE_REALLOC)),
                    free: ptr::read_volatile(ptr::addr_of!(DECODER_RANGE_FREE)),
                };
                DECODER_INITIAL_POSITION = initial_position;
                DECODER_NEXT_RANGE = next_range;
                DECODER_SHIFT_TABLE = TABLE.as_ptr();
                DECODER_RANGE_REALLOC = reallocate;
                DECODER_RANGE_FREE = release;
                fixture
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                DECODER_INITIAL_POSITION = self.initial;
                DECODER_NEXT_RANGE = self.next;
                DECODER_SHIFT_TABLE = self.table;
                DECODER_RANGE_REALLOC = self.realloc;
                DECODER_RANGE_FREE = self.free;
            }
        }
    }

    #[test]
    fn collects_ceiling_unit_count_and_terminates_the_list() {
        let _lock = TEST_LOCK.lock();
        let _fixture = Fixture::install(&[(1, 101), (1, 102)]);
        let mut state = [0u32; 8];
        state[STATE_BIT_COUNT_WORD] = 513;
        let segments = unsafe { decoder_range_segments(0, state.as_mut_ptr()) };
        assert!(!segments.is_null());
        unsafe {
            assert_eq!(*segments.add(0), DecoderRangeSegment { start: 100, length: 1 });
            assert_eq!(*segments.add(1), DecoderRangeSegment { start: 101, length: 1 });
            assert_eq!(*segments.add(2), DecoderRangeSegment { start: 0, length: 0 });
            range_free(segments.cast());
        }
    }

    #[test]
    fn frees_partial_segments_when_the_decoder_returns_no_range() {
        let _lock = TEST_LOCK.lock();
        let _fixture = Fixture::install(&[(1, 101), (0, 0)]);
        let mut state = [0u32; 8];
        state[STATE_BIT_COUNT_WORD] = 513;
        assert!(unsafe { decoder_range_segments(0, state.as_mut_ptr()) }.is_null());
        assert_eq!(unsafe { FREE_COUNT }, 1);
    }
}
