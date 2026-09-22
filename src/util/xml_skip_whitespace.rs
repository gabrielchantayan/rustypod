//! `xml_skip_whitespace` — original: `FUN_0825d354` @ `0x0825d354`
//! (**48 bytes**, `0x0825d354..0x0825d383`; extent verified against the
//! following function at `0x0825d384`).
//!
//! Decodes one XML UTF-8 codepoint at a time and discards XML whitespace
//! (`U+0020`, `U+0009`, `U+000D`, or `U+000A`) until the first other value,
//! including the `u32::MAX` decoder error/EOF sentinel. It has 26 verified
//! static `bl` call sites: 25 unconditional and one `blne` at `0x0825d180`.
//!
//! `FUN_0825d2fc` is now ported as
//! [`super::xml_codepoint_is_whitespace::xml_codepoint_is_whitespace`].

use super::xml_decode_codepoint_and_reset::{
    xml_decode_codepoint_and_reset, XmlUtf8Decoder,
};

use super::xml_codepoint_is_whitespace::xml_codepoint_is_whitespace;

/// `xml_skip_whitespace` — original: `FUN_0825d354` @ `0x0825d354`
/// (48 bytes; 26 binary-verified static `bl` call sites).
///
/// Dereferences `reader_slot` without a NULL check, then repeatedly decodes
/// and classifies codepoints directly with the ported predicate. The first
/// codepoint whose predicate result is zero is returned unchanged. Any nonzero
/// predicate result continues the loop, matching the ARM `cmp r0,#0; bne`
/// rather than assuming a normalized boolean result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn xml_skip_whitespace(reader_slot: *mut *mut u8) -> u32 {
    loop {
        let codepoint = unsafe {
            xml_decode_codepoint_and_reset(reader_slot.read().cast::<XmlUtf8Decoder>())
        };
        if unsafe { xml_codepoint_is_whitespace(reader_slot, codepoint, codepoint) } == 0 {
            return codepoint;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use super::super::xml_decode_codepoint_and_reset::{
        XmlCodepointDecoderOps, XmlUtf8Decoder, DEFAULT_XML_CODEPOINT_DECODER_OPS,
        XML_CODEPOINT_DECODER_OPS, XML_CODEPOINT_DECODER_OPS_LOCK,
    };
    use core::ptr;
    use std::sync::MutexGuard;
    use std::vec::Vec;
    static mut DECODED: Vec<u32> = Vec::new();
    static mut DECODE_INDEX: usize = 0;

    unsafe extern "C" fn queued_next_codepoint(_reader: *mut XmlUtf8Decoder) -> u32 {
        let index = unsafe { ptr::addr_of!(DECODE_INDEX).read_volatile() };
        let value = unsafe { (&*ptr::addr_of!(DECODED))[index] };
        unsafe { ptr::addr_of_mut!(DECODE_INDEX).write_volatile(index + 1) };
        value
    }

    fn install(decoded: &[u32]) -> MutexGuard<'static, ()> {
        let guard = XML_CODEPOINT_DECODER_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            XML_CODEPOINT_DECODER_OPS = XmlCodepointDecoderOps {
                decode_codepoint: queued_next_codepoint,
            };
            *ptr::addr_of_mut!(DECODED) = decoded.to_vec();
            DECODE_INDEX = 0;
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            XML_CODEPOINT_DECODER_OPS = DEFAULT_XML_CODEPOINT_DECODER_OPS;
            (*ptr::addr_of_mut!(DECODED)).clear();
            DECODE_INDEX = 0;
        }
        drop(guard);
    }

    #[test]
    fn returns_the_first_non_whitespace_codepoint() {
        let guard = install(&[b'<' as u32]);
        let mut decoder = XmlUtf8Decoder {
            callback_table: 0,
            state: 6,
            codepoint: 0,
        };
        let mut reader = ptr::addr_of_mut!(decoder).cast::<u8>();
        let reader_slot = ptr::addr_of_mut!(reader);
        unsafe {
            assert_eq!(xml_skip_whitespace(reader_slot), b'<' as u32);
        }
        restore(guard);
    }

    #[test]
    fn skips_all_four_xml_whitespace_codepoints_in_order() {
        let guard = install(&[0x20, 0x09, 0x0d, 0x0a, b'X' as u32]);
        let mut decoder = XmlUtf8Decoder {
            callback_table: 0,
            state: 3,
            codepoint: 0,
        };
        let mut reader = ptr::addr_of_mut!(decoder).cast::<u8>();
        let reader_slot = ptr::addr_of_mut!(reader);
        unsafe {
            assert_eq!(xml_skip_whitespace(reader_slot), b'X' as u32);
            assert_eq!(ptr::addr_of!(DECODE_INDEX).read_volatile(), 5);
        }
        restore(guard);
    }

    #[test]
    fn returns_decoder_eof_sentinel_without_another_decode() {
        let guard = install(&[u32::MAX]);
        let mut decoder = XmlUtf8Decoder {
            callback_table: 0,
            state: 4,
            codepoint: 0,
        };
        let mut reader = ptr::addr_of_mut!(decoder).cast::<u8>();
        let reader_slot = ptr::addr_of_mut!(reader);
        unsafe {
            assert_eq!(xml_skip_whitespace(reader_slot), u32::MAX);
            assert_eq!(ptr::addr_of!(DECODE_INDEX).read_volatile(), 1);
        }
        restore(guard);
    }
}
