//! `xml_collect_until_delimiter` — original: `FUN_0825d424` @ `0x0825d424`
//! (**160 bytes**, `0x0825d424..0x0825d4c3`; the next real function starts at
//! `0x0825d4c4`). Four inbound direct `bl` call sites are binary-verified
//! (`0x0825cc60`, `0x0825d0e0`, `0x0825d294`, and `0x0825d4d8`), all plain;
//! no predicated inbound `bl` reaches this address.
//!
//! Default-constructs `output`, then consumes UTF-8 codepoints until the input
//! is exhausted or either delimiter is seen. Each retained codepoint appends
//! its low byte to the COW string. With `trim_trailing_whitespace`, whitespace
//! ends collection only after at least one retained byte; leading whitespace is
//! retained. Deliberate deviation: the raw `basic_string::replace(pos, 0, 1,
//! char)` call at `0x083d888c` is unported, so this invokes its already-ported
//! `cxx_string_replace_core` implementation directly.

use crate::cxx::string::{cxx_string_default_ctor, cxx_string_replace_core};
use super::xml_decode_codepoint_and_reset::{XmlCodepointDecoderOps, XmlUtf8Decoder, XML_CODEPOINT_DECODER_OPS};
use super::xml_input_is_exhausted::{xml_input_is_exhausted, XmlInput};
use super::xml_skip_whitespace::{XmlWhitespaceOps, XML_WHITESPACE_OPS};

#[inline(always)]
unsafe fn decoder_ops() -> XmlCodepointDecoderOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(XML_CODEPOINT_DECODER_OPS)) }
}

#[inline(always)]
unsafe fn whitespace_ops() -> XmlWhitespaceOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(XML_WHITESPACE_OPS)) }
}

/// Collects XML input bytes through either delimiter.
///
/// The first decode deliberately calls the raw UTF-8 decoder without clearing
/// its state; subsequent decodes use the reset wrapper. The string length is
/// read before each one-byte splice, matching the original's `ldr [data,#-4]`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn xml_collect_until_delimiter(
    output: *mut *mut u8,
    input_slot: *mut *mut XmlInput,
    first_delimiter: u32,
    second_delimiter: u32,
    trim_trailing_whitespace: u32,
) {
    unsafe { cxx_string_default_ctor(output); }
    loop {
        if unsafe { xml_input_is_exhausted(input_slot.read()) } != 0 {
            return;
        }
        let input = unsafe { input_slot.read() };
        let codepoint = unsafe { (decoder_ops().decode_codepoint)(input.cast::<XmlUtf8Decoder>()) };
        if codepoint == first_delimiter || codepoint == second_delimiter {
            return;
        }
        let codepoint = unsafe { super::xml_decode_codepoint_and_reset::xml_decode_codepoint_and_reset(input.cast::<XmlUtf8Decoder>()) };
        if trim_trailing_whitespace != 0
            && unsafe { (whitespace_ops().is_xml_whitespace)(input_slot.cast(), codepoint, codepoint) } != 0
            && unsafe { (*output).sub(4).cast::<u32>().read() } != 0
        {
            return;
        }
        let length = unsafe { (*output).sub(4).cast::<u32>().read() };
        let byte = (codepoint & 0xff) as u8;
        unsafe { cxx_string_replace_core(output, length, 0, &byte, 1, 0, 1); }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use super::super::xml_decode_codepoint_and_reset::{DEFAULT_XML_CODEPOINT_DECODER_OPS, XML_CODEPOINT_DECODER_OPS_LOCK};
    use super::super::xml_input_is_exhausted::{DEFAULT_XML_INPUT_OPS, XmlInputOps, XML_INPUT_OPS};
    use super::super::xml_skip_whitespace::DEFAULT_XML_WHITESPACE_OPS;
    use core::ptr;

    static mut CODEPOINTS: [u32; 4] = [0; 4];
    static mut INDEX: usize = 0;
    static mut EXHAUSTED_AFTER: usize = 0;
    static mut RESETS: u32 = 0;

    unsafe extern "C" fn next_codepoint(_input: *mut XmlUtf8Decoder) -> u32 {
        unsafe {
            let value = CODEPOINTS[INDEX];
            INDEX += 1;
            value
        }
    }

    unsafe extern "C" fn exhausted(_input: *mut XmlInput) -> u32 {
        unsafe { u32::from(INDEX >= EXHAUSTED_AFTER) }
    }

    unsafe extern "C" fn whitespace(_slot: *mut *mut u8, codepoint: u32, duplicate: u32) -> u32 {
        assert_eq!(codepoint, duplicate);
        unsafe { RESETS += 1; }
        u32::from(matches!(codepoint, 0x20 | 9 | 10 | 13))
    }

    fn install(values: &[u32], exhausted_after: usize) {
        unsafe {
            CODEPOINTS = [0; 4];
            CODEPOINTS[..values.len()].copy_from_slice(values);
            INDEX = 0;
            EXHAUSTED_AFTER = exhausted_after;
            RESETS = 0;
            XML_CODEPOINT_DECODER_OPS = XmlCodepointDecoderOps { decode_codepoint: next_codepoint };
            XML_INPUT_OPS = XmlInputOps { is_exhausted: exhausted };
            XML_WHITESPACE_OPS = XmlWhitespaceOps { is_xml_whitespace: whitespace };
        }
    }

    fn restore() {
        unsafe {
            XML_CODEPOINT_DECODER_OPS = DEFAULT_XML_CODEPOINT_DECODER_OPS;
            XML_INPUT_OPS = DEFAULT_XML_INPUT_OPS;
            XML_WHITESPACE_OPS = DEFAULT_XML_WHITESPACE_OPS;
        }
    }

    #[test]
    fn stops_before_a_delimiter_without_resetting_it() {
        let _guard = XML_CODEPOINT_DECODER_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        install(&[b'>'.into()], 1);
        let mut input = XmlInput { vtable: 0, status: 0 };
        let mut slot: *mut XmlInput = &mut input;
        let mut output = ptr::null_mut();
        unsafe { xml_collect_until_delimiter(&mut output, &mut slot, b'>' as u32, 0, 1); }
        assert_eq!(unsafe { INDEX }, 1);
        assert_eq!(unsafe { RESETS }, 0);
        restore();
    }

    #[test]
    fn stops_before_the_second_delimiter() {
        let _guard = XML_CODEPOINT_DECODER_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        install(&[b'/'.into()], 1);
        let mut input = XmlInput { vtable: 0, status: 0 };
        let mut slot: *mut XmlInput = &mut input;
        let mut output = ptr::null_mut();
        unsafe { xml_collect_until_delimiter(&mut output, &mut slot, b'>' as u32, b'/' as u32, 1); }
        assert_eq!(unsafe { INDEX }, 1);
        assert_eq!(unsafe { RESETS }, 0);
        restore();
    }

    #[test]
    fn exhausted_input_leaves_the_default_constructed_output() {
        let _guard = XML_CODEPOINT_DECODER_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        install(&[], 0);
        let mut input = XmlInput { vtable: 0, status: 0 };
        let mut slot: *mut XmlInput = &mut input;
        let mut output = ptr::null_mut();
        unsafe { xml_collect_until_delimiter(&mut output, &mut slot, b'>' as u32, 0, 0); }
        assert!(!output.is_null());
        assert_eq!(unsafe { INDEX }, 0);
        restore();
    }
}
