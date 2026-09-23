//! Starts recursive MOV atom-range parsing — `FUN_081f3d68` @ **0x081f3d68**.
//!
//! Raw `osos.dec` establishes the exact 156-byte extent
//! `0x081f3d68..0x081f3e04`; `0x081f3e04` starts the recursive helper.
//! Whole-image A32 decoding finds three incoming plain `bl` callers
//! (`0x0812113c`, `0x081e600c`, and `0x0820c714`) and no predicated forms.
//! The body has one direct plain `bl` to the recursive helper at `0x081f3e04`,
//! no predicated `bl`, and one indirect `blx` through the reader vtable +0x14.
//!
//! Algorithm: ask the reader to consume the initial 64-bit range with flag
//! zero. On failure return one. Otherwise normalize the `-1/-1` range to
//! `-1/0x7fffffff`, initialize the recursion counter to zero, and invoke the
//! recursive atom parser with the consumed range as both its initial offset
//! and its limit. Return zero after that helper returns.
//!
//! Deliberate deviation: the unported recursive helper has no established
//! semantic identity beyond its verified ABI, so target builds call its fixed
//! retail address. Host builds use volatile operation seams for both calls;
//! this avoids representing target-width function pointers as host pointers.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_PARSE_ATOM_RANGE: usize = 0x081f_3e04;

/// ABI of the reader's vtable +0x14 range-consumption operation.
pub type MovConsumeRange = unsafe extern "C" fn(*mut u8, u32, u32, u32, u32) -> u32;

/// ABI of the recursive atom-range parser at 0x081f3e04.
pub type MovParseAtomRange = unsafe extern "C" fn(
    *mut u8,
    *mut u8,
    *mut u8,
    *mut u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    *mut u32,
);

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct MovAtomRangeParseOps {
    pub consume_range: MovConsumeRange,
    pub parse_range: MovParseAtomRange,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_consume_range(
    _reader: *mut u8,
    _self: u32,
    _offset_lo: u32,
    _offset_hi: u32,
    _flag: u32,
) -> u32 {
    panic!("install MOV atom-range parser host operations before calling this wrapper")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_parse_range(
    _parser: *mut u8,
    _reader: *mut u8,
    _node: *mut u8,
    _counter: *mut u32,
    _range_lo: u32,
    _range_hi: u32,
    _offset_lo: u32,
    _offset_hi: u32,
    _limit_lo: u32,
    _limit_hi: u32,
    _counter_again: *mut u32,
) {
    panic!("install MOV atom-range parser host operations before calling this wrapper")
}

#[cfg(not(target_os = "none"))]
pub static mut MOV_ATOM_RANGE_PARSE_OPS: MovAtomRangeParseOps = MovAtomRangeParseOps {
    consume_range: missing_consume_range,
    parse_range: missing_parse_range,
};

#[inline(always)]
unsafe fn consume_range(reader: *mut u8, offset_lo: u32, offset_hi: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let vtable = unsafe { core::ptr::read_volatile(reader.cast::<u32>()) };
        let operation = unsafe { core::ptr::read_volatile((vtable as usize as *const u32).add(5)) };
        let consume: MovConsumeRange = unsafe { core::mem::transmute(operation as usize) };
        return unsafe { consume(reader, operation, offset_lo, offset_hi, 0) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let consume = unsafe { core::ptr::read_volatile(addr_of!(MOV_ATOM_RANGE_PARSE_OPS.consume_range)) };
        unsafe { consume(reader, 0, offset_lo, offset_hi, 0) }
    }
}

#[inline(always)]
unsafe fn parse_atom_range(
    parser: *mut u8,
    reader: *mut u8,
    node: *mut u8,
    counter: *mut u32,
    range_lo: u32,
    range_hi: u32,
    offset_lo: u32,
    offset_hi: u32,
) {
    #[cfg(target_os = "none")]
    {
        let parse: MovParseAtomRange = unsafe { core::mem::transmute(RETAIL_PARSE_ATOM_RANGE) };
        return unsafe { parse(parser, reader, node, counter, range_lo, range_hi, offset_lo, offset_hi, offset_lo, offset_hi, counter) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let parse = unsafe { core::ptr::read_volatile(addr_of!(MOV_ATOM_RANGE_PARSE_OPS.parse_range)) };
        unsafe { parse(parser, reader, node, counter, range_lo, range_hi, offset_lo, offset_hi, offset_lo, offset_hi, counter) }
    }
}

/// Consumes an initial range then starts recursive MOV atom parsing.
///
/// # Safety
///
/// `reader` must be a retail reader object whose vtable +0x14 operation
/// accepts this range; `parser` and `node` must satisfy the recursive helper.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.mov_atom_range_parse")]
pub unsafe extern "C" fn mov_atom_range_parse(
    parser: *mut u8,
    reader: *mut u8,
    offset_lo: u32,
    offset_hi: u32,
    node: *mut u8,
    _unused: u32,
    mut range_lo: u32,
    mut range_hi: u32,
) -> u32 {
    if unsafe { consume_range(reader, offset_lo, offset_hi) } != 0 {
        return 1;
    }
    if range_lo == u32::MAX && range_hi == u32::MAX {
        range_lo = u32::MAX;
        range_hi = 0x7fff_ffff;
    }
    let mut counter = 0;
    unsafe { parse_atom_range(parser, reader, node, &mut counter, range_lo, range_hi, offset_lo, offset_hi) };
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::addr_of_mut;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CONSUME_RESULT: u32 = 0;
    static mut CONSUME_CALL: Option<(usize, u32, u32, u32, u32)> = None;
    static mut PARSE_CALL: Option<(usize, usize, usize, u32, u32, u32, u32, u32, u32, bool)> = None;

    unsafe extern "C" fn record_consume(reader: *mut u8, operation: u32, lo: u32, hi: u32, flag: u32) -> u32 {
        unsafe { CONSUME_CALL = Some((reader as usize, operation, lo, hi, flag)); CONSUME_RESULT }
    }

    unsafe extern "C" fn record_parse(
        parser: *mut u8, reader: *mut u8, node: *mut u8, counter: *mut u32,
        range_lo: u32, range_hi: u32, offset_lo: u32, offset_hi: u32,
        limit_lo: u32, limit_hi: u32, counter_again: *mut u32,
    ) {
        unsafe { PARSE_CALL = Some((parser as usize, reader as usize, node as usize, range_lo, range_hi, offset_lo, offset_hi, limit_lo, limit_hi, counter == counter_again && counter.read() == 0)) }
    }

    fn install(result: u32) {
        unsafe {
            MOV_ATOM_RANGE_PARSE_OPS = MovAtomRangeParseOps { consume_range: record_consume, parse_range: record_parse };
            CONSUME_RESULT = result;
            CONSUME_CALL = None;
            PARSE_CALL = None;
        }
    }

    #[test]
    fn returns_one_without_recursing_when_initial_consumption_fails() {
        let _guard = LOCK.lock();
        install(9);
        assert_eq!(unsafe { mov_atom_range_parse(1usize as *mut u8, 2usize as *mut u8, 3, 4, 5usize as *mut u8, 6, 7, 8) }, 1);
        assert_eq!(unsafe { CONSUME_CALL }, Some((2, 0, 3, 4, 0)));
        assert_eq!(unsafe { PARSE_CALL }, None);
    }

    #[test]
    fn normalizes_unbounded_range_and_duplicates_initial_offset_as_limit() {
        let _guard = LOCK.lock();
        install(0);
        assert_eq!(unsafe { mov_atom_range_parse(1usize as *mut u8, 2usize as *mut u8, 3, 4, 5usize as *mut u8, 6, u32::MAX, u32::MAX) }, 0);
        assert_eq!(unsafe { PARSE_CALL }, Some((1, 2, 5, u32::MAX, 0x7fff_ffff, 3, 4, 3, 4, true)));
    }

    #[test]
    fn preserves_non_sentinel_range() {
        let _guard = LOCK.lock();
        install(0);
        assert_eq!(unsafe { mov_atom_range_parse(1usize as *mut u8, 2usize as *mut u8, 0x11, 0x22, 3usize as *mut u8, 0, 0x33, 0x44) }, 0);
        assert_eq!(unsafe { PARSE_CALL }, Some((1, 2, 3, 0x33, 0x44, 0x11, 0x22, 0x11, 0x22, true)));
    }
}
