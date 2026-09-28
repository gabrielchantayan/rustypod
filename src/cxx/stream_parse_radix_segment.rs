//! `stream_parse_radix_segment` — original: `FUN_083b6798` @ load address
//! **0x083b6798**.
//!
//! Raw ARM disassembly establishes the 164-byte extent
//! 0x083b6798..0x083b6838: `pop {r4,r5,r6,pc}` is followed by the separately
//! linked radix-digit parser at 0x083b683c. The body contains five direct,
//! unconditional plain `bl` instructions (to 0x083b683c, 0x083d6504,
//! 0x083d7158, 0x083daf50, and itself), and zero predicated `bl` instructions.
//! It first parses one radix segment, rejects an exhausted 40-byte output
//! scratch area or a segment length of 255 or more, otherwise prefixes the
//! segment with its byte length. When both stream buffers still agree and the
//! input next byte is the configured delimiter, it consumes that delimiter and
//! parses the following segment recursively.
//!
//! # Deliberate deviations
//!
//! The adjacent radix-digit parser at 0x083b683c is not yet ported. ARM builds
//! tail-branch to that verified raw address; host tests install a recorder for
//! that one unavailable helper.

use super::streambuf_slot_consume::streambuf_slot_consume;
use super::streambuf_slot_peek_byte::streambuf_slot_peek_byte;
use super::streambuf_slot_peek_equal::{streambuf_slot_peek_equal, StreambufSlotPairContext};

/// Target-width parser state fields read by [`stream_parse_radix_segment`].
#[repr(C)]
pub struct RadixSegmentContext {
    flags: u32,
    unused_before_streambuf_slots: [u32; 26],
    input_streambuf_slot: u32,
    comparison_streambuf_slot: u32,
    unused_before_delimiter: u32,
    delimiter: u32,
    unused_before_output_cursor: [u32; 10],
    output_cursor: u32,
}

const _: [u8; 0x6c] = [0; core::mem::offset_of!(RadixSegmentContext, input_streambuf_slot)];
const _: [u8; 0x70] = [0; core::mem::offset_of!(RadixSegmentContext, comparison_streambuf_slot)];
const _: [u8; 0x78] = [0; core::mem::offset_of!(RadixSegmentContext, delimiter)];
const _: [u8; 0xa4] = [0; core::mem::offset_of!(RadixSegmentContext, output_cursor)];

#[cfg(target_arch = "arm")]
extern "C" {
    fn parse_radix_digits_raw(context: *mut RadixSegmentContext, output: *mut u8, preserve_zero: u32) -> *mut u8;
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .section .text.parse_radix_digits_raw, "ax", %progbits
    .p2align 2
    .globl parse_radix_digits_raw
    .type parse_radix_digits_raw, %function
parse_radix_digits_raw:
    b       0x083b683c
    .size parse_radix_digits_raw, . - parse_radix_digits_raw
"#
);

#[cfg(not(target_arch = "arm"))]
pub(crate) type ParseRadixDigits = unsafe extern "C" fn(*mut RadixSegmentContext, *mut u8, u32) -> *mut u8;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn unavailable_parse_radix_digits(_context: *mut RadixSegmentContext, output: *mut u8, _preserve_zero: u32) -> *mut u8 {
    output
}

#[cfg(not(target_arch = "arm"))]
pub(crate) static mut PARSE_RADIX_DIGITS: ParseRadixDigits = unavailable_parse_radix_digits;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn parse_radix_digits_raw(context: *mut RadixSegmentContext, output: *mut u8, preserve_zero: u32) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(PARSE_RADIX_DIGITS))(context, output, preserve_zero)
}

/// stream_parse_radix_segment — original: `FUN_083b6798` @ 0x083b6798
/// (164 bytes; five unconditional plain `bl` instructions, zero predicated).
///
/// Parses radix digits into `output`, prefixes a non-empty segment shorter than
/// 255 bytes with its length, and recursively parses a delimiter-separated next
/// segment only while the context's two stream buffers compare equal.
///
/// # Safety
///
/// `context` must describe the target-width layout above. Its cursor and both
/// stream-buffer slots must be valid for their respective retailOS helpers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stream_parse_radix_segment(context: *mut RadixSegmentContext, output: *mut u8) -> *mut u8 {
    let parsed_end = parse_radix_digits_raw(context, output, 0);
    let cursor = (*context).output_cursor as *mut u8;

    if cursor == (context.cast::<u8>()).add(0xa1) {
        (*context).flags |= 4;
        return parsed_end;
    }

    let segment_len = (parsed_end as usize).wrapping_sub(output as usize) as i32;
    if segment_len >= 0xff {
        (*context).flags |= 8;
        return parsed_end;
    }
    if segment_len == 0 {
        return parsed_end;
    }

    (*context).output_cursor = cursor.add(1) as usize as u32;
    cursor.write(segment_len as u8);

    if !streambuf_slot_peek_equal(context.cast::<StreambufSlotPairContext>()) {
        return parsed_end;
    }
    if streambuf_slot_peek_byte(core::ptr::addr_of!((*context).input_streambuf_slot)) != (*context).delimiter as u8 {
        return parsed_end;
    }

    streambuf_slot_consume(core::ptr::addr_of_mut!((*context).input_streambuf_slot));
    stream_parse_radix_segment(context, parsed_end)
}

#[cfg(test)]
pub(crate) static STREAM_PARSE_RADIX_SEGMENT_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::streambuf_slot_consume::{StreambufConsume, STREAMBUF_CONSUME, STREAMBUF_CONSUME_TEST_LOCK};
    use crate::cxx::string::{StreambufUnderflowHook, STREAMBUF_UNDERFLOW, STREAMBUF_UNDERFLOW_TEST_LOCK};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    const INPUT_SLOT_OFFSET: usize = 0x200;
    const COMPARISON_SLOT_OFFSET: usize = 0x204;
    const INPUT_STREAMBUF_OFFSET: usize = 0x300;
    const COMPARISON_STREAMBUF_OFFSET: usize = 0x400;
    const OUTPUT_OFFSET: usize = 0x500;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::STREAM_PARSE_RADIX_SEGMENT, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static PARSER_RESULTS: Mutex<([usize; 2], usize)> = Mutex::new(([0; 2], 0));
    static PEEK_RESULT: Mutex<i32> = Mutex::new(0);
    static CONSUME_COUNT: Mutex<usize> = Mutex::new(0);

    unsafe extern "C" fn parse_recording(_context: *mut RadixSegmentContext, output: *mut u8, preserve_zero: u32) -> *mut u8 {
        assert_eq!(preserve_zero, 0);
        let mut parser = PARSER_RESULTS.lock().unwrap_or_else(|poison| poison.into_inner());
        let index = parser.1;
        parser.1 += 1;
        if parser.0[index] == 0 { output } else { parser.0[index] as *mut u8 }
    }

    unsafe extern "C" fn peek_recording(_streambuf: *mut u8) -> i32 {
        *PEEK_RESULT.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    unsafe extern "C" fn consume_recording(_streambuf: *mut u8) {
        *CONSUME_COUNT.lock().unwrap_or_else(|poison| poison.into_inner()) += 1;
    }

    struct Reset(ParseRadixDigits, StreambufUnderflowHook, StreambufConsume);
    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                PARSE_RADIX_DIGITS = self.0;
                STREAMBUF_UNDERFLOW = self.1;
                STREAMBUF_CONSUME = self.2;
            }
        }
    }

    unsafe fn fixture() -> Option<(*mut RadixSegmentContext, *mut u8)> {
        let Some(base) = *FIXTURE else {
            return None;
        };
        let base = base as *mut u8;
        ptr::write_bytes(base, 0, FIXTURE_LEN);
        let context = base.cast::<RadixSegmentContext>();
        (*context).input_streambuf_slot = base.add(INPUT_SLOT_OFFSET) as usize as u32;
        (*context).comparison_streambuf_slot = base.add(COMPARISON_SLOT_OFFSET) as usize as u32;
        (base.add(INPUT_SLOT_OFFSET).cast::<u32>()).write(base.add(INPUT_STREAMBUF_OFFSET) as usize as u32);
        (base.add(COMPARISON_SLOT_OFFSET).cast::<u32>()).write(base.add(COMPARISON_STREAMBUF_OFFSET) as usize as u32);
        (*context).output_cursor = base.add(OUTPUT_OFFSET) as usize as u32;
        Some((context, base.add(OUTPUT_OFFSET)))
    }

    unsafe fn install(parser_results: [usize; 2], peek_result: i32) -> Reset {
        *PARSER_RESULTS.lock().unwrap_or_else(|poison| poison.into_inner()) = (parser_results, 0);
        *PEEK_RESULT.lock().unwrap_or_else(|poison| poison.into_inner()) = peek_result;
        *CONSUME_COUNT.lock().unwrap_or_else(|poison| poison.into_inner()) = 0;
        let old_parser = core::ptr::read_volatile(core::ptr::addr_of!(PARSE_RADIX_DIGITS));
        let old_peek = core::ptr::read_volatile(core::ptr::addr_of!(STREAMBUF_UNDERFLOW));
        let old_consume = core::ptr::read_volatile(core::ptr::addr_of!(STREAMBUF_CONSUME));
        PARSE_RADIX_DIGITS = parse_recording;
        STREAMBUF_UNDERFLOW = peek_recording;
        STREAMBUF_CONSUME = consume_recording;
        Reset(old_parser, old_peek, old_consume)
    }

    #[test]
    fn marks_full_scratch_area_without_storing() {
        let _test_guard = STREAM_PARSE_RADIX_SEGMENT_TEST_LOCK.lock();
        let _peek_guard = STREAMBUF_UNDERFLOW_TEST_LOCK.lock();
        let _consume_guard = STREAMBUF_CONSUME_TEST_LOCK.lock();
        let Some((context, output)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("cxx/stream_parse_radix_segment"));
            return;
        };
        unsafe {
            (*context).output_cursor = context.cast::<u8>().add(0xa1) as usize as u32;
            let _reset = install([output.add(3) as usize, 0], 0);
            assert_eq!(stream_parse_radix_segment(context, output), output.add(3));
            assert_eq!((*context).flags, 4);
        }
    }

    #[test]
    fn rejects_segments_of_255_bytes() {
        let _test_guard = STREAM_PARSE_RADIX_SEGMENT_TEST_LOCK.lock();
        let _peek_guard = STREAMBUF_UNDERFLOW_TEST_LOCK.lock();
        let _consume_guard = STREAMBUF_CONSUME_TEST_LOCK.lock();
        let Some((context, output)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("cxx/stream_parse_radix_segment"));
            return;
        };
        unsafe {
            let _reset = install([output.add(255) as usize, 0], 0);
            assert_eq!(stream_parse_radix_segment(context, output), output.add(255));
            assert_eq!((*context).flags, 8);
            assert_eq!((*context).output_cursor as usize, output as usize);
        }
    }

    #[test]
    fn stores_length_and_recurses_after_matching_delimiter() {
        let _test_guard = STREAM_PARSE_RADIX_SEGMENT_TEST_LOCK.lock();
        let _peek_guard = STREAMBUF_UNDERFLOW_TEST_LOCK.lock();
        let _consume_guard = STREAMBUF_CONSUME_TEST_LOCK.lock();
        let Some((context, output)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("cxx/stream_parse_radix_segment"));
            return;
        };
        unsafe {
            (*context).delimiter = b',' as u32;
            let _reset = install([output.add(3) as usize, output.add(3) as usize], b',' as i32);
            assert_eq!(stream_parse_radix_segment(context, output), output.add(3));
            assert_eq!(*output, 3);
            assert_eq!((*context).output_cursor as usize, output.add(1) as usize);
        }
        assert_eq!(*CONSUME_COUNT.lock().unwrap_or_else(|poison| poison.into_inner()), 1);
        assert_eq!(PARSER_RESULTS.lock().unwrap_or_else(|poison| poison.into_inner()).1, 2);
    }
}
