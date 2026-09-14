//! `format_field_padding` — original: `FUN_080ec120` @ 0x080ec120 (72 bytes).
//!
//! Raw ARM establishes the exact 18-instruction extent from 0x080ec120
//! through 0x080ec164; the separately linked sibling begins at 0x080ec168.
//! Decoding every ARM `B`/`BL` immediate in `osos.dec` finds six direct `bl`
//! callers, all unconditional (0x08077e84, 0x08077ec8, 0x080e95c8,
//! 0x080e95f0, 0x080ec0e8, and 0x080ec110), with no predicated calls.
//!
//! When both the padding control word and phase are nonzero, compares the
//! signed logical text length with the signed field width, then emits the
//! configured fill byte until the width is reached. Each byte uses the ported
//! bounded-output helper, so attempted-byte accounting and output truncation
//! exactly remain its responsibility. Stock has no NULL guard. No deliberate
//! behavioral deviations.

use crate::printf::format_bounded_byte::format_bounded_byte;
use crate::printf::printf_radix_integer::RadixFormatSpec;

/// Emit this phase's configured field padding. Port of `FUN_080ec120` @
/// 0x080ec120.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn format_field_padding(phase: u32, spec: *mut RadixFormatSpec) {
    let padding_enabled = core::ptr::read_volatile(core::ptr::addr_of!((*spec).padding_enabled));
    if padding_enabled == 0 || phase == 0 {
        return;
    }

    let mut position = (*spec).text_len;
    if (position as i32) >= (*spec).width {
        return;
    }

    while (position as i32) < (*spec).width {
        format_bounded_byte(spec, (*spec).fill);
        position = position.wrapping_add(1);
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

    fn state(sink: &mut Sink) -> RadixFormatSpec {
        RadixFormatSpec {
            write_byte: collect_byte,
            write_context: sink as *mut Sink as *mut c_void,
            emitted: 0,
            limit: u32::MAX,
            padding_enabled: 1,
            left_justify: 0,
            precision_specified: 0,
            show_plus: 0,
            text_len: 0,
            width: 0,
            precision: 0,
            fill: b' ',
            reserved_2d: [0; 3],
        }
    }

    #[test]
    fn pads_from_logical_text_length_to_signed_width() {
        let _lock = CALLBACK_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut sink = Sink { bytes: Vec::new() };
        let mut spec = state(&mut sink);
        spec.text_len = 2;
        spec.width = 5;
        spec.fill = b'.';

        unsafe { format_field_padding(1, &mut spec) };

        assert_eq!(sink.bytes, b"...");
        assert_eq!(spec.emitted, 3);
        assert_eq!(spec.text_len, 2);
    }

    #[test]
    fn phase_or_control_word_disables_padding_and_negative_width_is_satisfied() {
        let _lock = CALLBACK_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut sink = Sink { bytes: Vec::new() };
        let mut spec = state(&mut sink);
        spec.text_len = 1;
        spec.width = 4;

        unsafe { format_field_padding(0, &mut spec) };
        spec.padding_enabled = 0;
        unsafe { format_field_padding(1, &mut spec) };
        spec.padding_enabled = 1;
        spec.width = -1;
        unsafe { format_field_padding(1, &mut spec) };

        assert!(sink.bytes.is_empty());
        assert_eq!(spec.emitted, 0);
    }

    #[test]
    fn accounts_all_padding_attempts_when_output_is_bounded() {
        let _lock = CALLBACK_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut sink = Sink { bytes: Vec::new() };
        let mut spec = state(&mut sink);
        spec.text_len = 1;
        spec.width = 4;
        spec.fill = b'_';
        spec.emitted = 2;
        spec.limit = 3;

        unsafe { format_field_padding(1, &mut spec) };

        assert_eq!(sink.bytes, b"_");
        assert_eq!(spec.emitted, 5);
    }
}
