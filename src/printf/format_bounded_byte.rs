//! `format_bounded_byte` — original: `FUN_08280f7c` @ 0x08280f7c (44 bytes).
//!
//! Binary-verified ARM extent: 11 instructions from 0x08280f7c through
//! 0x08280fa4; the separately linked sibling begins at 0x08280fa8. A full
//! ARM B/BL-immediate decode of `osos.dec` finds seven direct `bl` callers,
//! all unconditional (0x08077e94, 0x08077ed8, 0x08077f0c, 0x08077f1c,
//! 0x080e95dc, 0x080ec0fc, and 0x080ec150), with no predicated or tail-branch
//! callers.
//!
//! Counts each attempted byte with wrapping `u32` arithmetic, then calls the
//! state-owned byte writer only when the count *before* incrementing was below
//! the unsigned output limit. Stock has no NULL guard for the state or its
//! callback. No deliberate behavioral deviations.

use crate::printf::printf_radix_integer::RadixFormatSpec;

/// Account for an attempted formatted byte and emit it if the output limit
/// permits it. Port of `FUN_08280f7c` @ 0x08280f7c.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn format_bounded_byte(spec: *mut RadixFormatSpec, byte: u8) {
    let previous = (*spec).emitted;
    (*spec).emitted = previous.wrapping_add(1);
    if previous < (*spec).limit {
        ((*spec).write_byte)(byte, (*spec).write_context);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ffi::c_void;
    use std::sync::Mutex;
    use std::vec::Vec;

    static CALLBACK_LOCK: Mutex<()> = Mutex::new(());

    struct Sink {
        bytes: Vec<u8>,
    }

    unsafe extern "C" fn collect_byte(byte: u8, context: *mut c_void) {
        (*(context as *mut Sink)).bytes.push(byte);
    }

    fn state(sink: &mut Sink, emitted: u32, limit: u32) -> RadixFormatSpec {
        RadixFormatSpec {
            write_byte: collect_byte,
            write_context: sink as *mut Sink as *mut c_void,
            emitted,
            limit,
            padding_enabled: 0,
            left_justify: 0,
            precision_specified: 0,
            show_plus: 0,
            text_len: 0,
            width: 0,
            precision: 0,
            fill: 0,
            reserved_2d: [0; 3],
        }
    }

    #[test]
    fn counts_attempts_but_stops_writing_at_unsigned_limit() {
        let _lock = CALLBACK_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut sink = Sink { bytes: Vec::new() };
        let mut spec = state(&mut sink, 0, 2);

        unsafe {
            format_bounded_byte(&mut spec, b'a');
            format_bounded_byte(&mut spec, b'b');
            format_bounded_byte(&mut spec, b'c');
        }

        assert_eq!(sink.bytes, b"ab");
        assert_eq!(spec.emitted, 3);
    }

    #[test]
    fn compares_before_incrementing_and_wraps_count() {
        let _lock = CALLBACK_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut sink = Sink { bytes: Vec::new() };
        let mut spec = state(&mut sink, u32::MAX, u32::MAX);

        unsafe {
            format_bounded_byte(&mut spec, b'x');
            format_bounded_byte(&mut spec, b'y');
        }

        assert_eq!(sink.bytes, b"y");
        assert_eq!(spec.emitted, 1);
    }
}
