//! Wide stream-buffer put — `FUN_083da7fc` @ load address `0x083da7fc`.
//! True extent: [0x083da7fc, 0x083da850), 84 bytes; the next function is
//! `mov pc, lr`. Whole-image raw A32 scan: one incoming plain BL at
//! 0x083d9d40, zero predicated BLs. Body: zero direct BLs, one indirect
//! `mov lr, pc; mov pc, r2` call through virtual slot +0x28.
//!
//! If flag 8 is set and the signed, wrapping byte difference between put
//! end and cursor, shifted right one, is nonzero, advance the cursor by two
//! bytes, store the halfword and return its zero-extended value. Otherwise
//! call the unresolved virtual slot with self and the zero-extended halfword,
//! returning its full result. Caller 0x083d9b20 flushes/converts two-byte
//! characters and ignores this result. No concrete virtual identity is guessed.
//!
//! Deliberate deviations: repr(C) pointers and vtable slots widen on hosts;
//! target field offsets remain +0x04 flags, +0x24 cursor, +0x28 end. Arithmetic
//! explicitly retains the firmware's wrapping 32-bit subtraction and ASR,
//! including its unusual behavior for negative differences. Rust expresses
//! the indirect ARM-state call as a typed C function pointer.

#[repr(C)]
pub struct WideStreambufVtable {
    pub reserved: [usize; 10],
    pub put: unsafe extern "C" fn(*mut WideStreambuf, u32) -> u32,
}

#[repr(C)]
pub struct WideStreambuf {
    pub vtable: *const WideStreambufVtable,
    pub flags: u32,
    pub reserved_08_20: [u32; 7],
    pub put_cursor: *mut u16,
    pub put_end: *mut u16,
}

/// # Safety
/// `buffer` must be a valid stream-buffer object. The buffered path requires
/// an aligned writable halfword at its cursor; the fallback requires a valid
/// virtual slot +0x28. Neither path checks NULL or repairs invalid ranges.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn wide_streambuf_put(buffer: *mut WideStreambuf, character: u16) -> u32 {
    if (*buffer).flags & 8 != 0 {
        let cursor = (*buffer).put_cursor;
        let difference = ((*buffer).put_end as usize as u32)
            .wrapping_sub(cursor as usize as u32) as i32;
        if difference >> 1 != 0 {
            (*buffer).put_cursor = cursor.wrapping_add(1);
            cursor.write(character);
            return character as u32;
        }
    }
    ((*(*buffer).vtable).put)(buffer, character as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn overflow(buffer: *mut WideStreambuf, character: u32) -> u32 {
        // A real state transition: enable a fresh put area and consume its
        // first position, while returning an EOF-like full-width result.
        (*buffer).flags |= 8;
        (*buffer).put_cursor.write(character as u16);
        (*buffer).put_cursor = (*buffer).put_cursor.wrapping_add(1);
        0xffff_ffff
    }

    fn fixture(cursor: *mut u16, end: *mut u16, flags: u32) -> WideStreambuf {
        static VTABLE: WideStreambufVtable = WideStreambufVtable {
            reserved: [0; 10], put: overflow,
        };
        WideStreambuf { vtable: &VTABLE, flags, reserved_08_20: [0x12345678; 7],
            put_cursor: cursor, put_end: end }
    }

    #[test]
    fn buffered_halfwords_preserve_neighbors_and_return_unsigned_values() {
        for character in [0, 0x7fff, 0x8000, 0xd800, 0xffff] {
            let mut words = [0x5555; 4];
            let cursor = unsafe { words.as_mut_ptr().add(1) };
            let mut buffer = fixture(cursor, unsafe { cursor.add(1) }, 0x108);
            assert_eq!(unsafe { wide_streambuf_put(&mut buffer, character) }, character as u32);
            assert_eq!(words, [0x5555, character, 0x5555, 0x5555]);
            assert_eq!(buffer.put_cursor, unsafe { cursor.add(1) });
            assert_eq!(buffer.flags, 0x108);
            assert_eq!(buffer.reserved_08_20, [0x12345678; 7]);
        }
    }

    #[test]
    fn disabled_full_and_single_byte_ranges_use_overflow_and_preserve_full_result() {
        for (flags, bytes) in [(0x100, 4), (8, 0), (8, 1)] {
            let mut words = [0x5555; 4];
            let cursor = words.as_mut_ptr();
            let end = cursor.cast::<u8>().wrapping_add(bytes).cast::<u16>();
            let mut buffer = fixture(cursor, end, flags);
            assert_eq!(unsafe { wide_streambuf_put(&mut buffer, 0xffff) }, 0xffff_ffff);
            assert_eq!(words, [0xffff, 0x5555, 0x5555, 0x5555]);
            assert_eq!(buffer.put_cursor, unsafe { cursor.add(1) });
            assert_eq!(buffer.flags, flags | 8);
            assert_eq!(buffer.put_end, end);
        }
    }

    #[test]
    fn negative_difference_still_takes_buffered_path() {
        let mut words = [0x5555; 4];
        let cursor = unsafe { words.as_mut_ptr().add(1) };
        let mut buffer = fixture(cursor, words.as_mut_ptr(), 8);
        assert_eq!(unsafe { wide_streambuf_put(&mut buffer, 0x8000) }, 0x8000);
        assert_eq!(words, [0x5555, 0x8000, 0x5555, 0x5555]);
        assert_eq!(buffer.put_cursor, unsafe { cursor.add(1) });
    }
}
