//! `xml_peek_second_skip_whitespace` — `FUN_0825d3d0` @ `0x0825d3d0`.
//! **84 bytes**, `0x0825d3d0..0x0825d423`; next prologue: `0x0825d424`.
//! Two verified inbound BL calls (0x0825cf94, 0x0825d154), both plain,
//! zero predicated; five plain outbound BL instructions, zero predicated.
//!
//! Saves the position before the active codepoint, runs the resetting
//! whitespace skipper twice, then the non-resetting skipper. Restores the
//! signed position with origin zero and returns the final codepoint, even at
//! EOF or if seeking fails. All direct callees are existing Rust ports;
//! opaque decoder/virtual methods retain their existing host seams. No
//! algorithmic deviations. The restore reader is reloaded from the slot.

use super::xml_decode_codepoint_and_reset::XmlUtf8Decoder;
use super::xml_decode_skip_whitespace::xml_decode_skip_whitespace;
use super::xml_reader_position_before_current::xml_reader_position_before_current;
use super::xml_reader_restore_position::xml_reader_restore_position;
use super::xml_skip_whitespace::xml_skip_whitespace;

/// Peek beyond two resetting whitespace skips without consuming input.
///
/// # Safety
/// `reader_slot` and its reader must remain valid for every decoder and
/// virtual method invocation. Like retailOS, there is no NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn xml_peek_second_skip_whitespace(reader_slot: *mut *mut u8) -> u32 {
    let position = unsafe {
        xml_reader_position_before_current(reader_slot.read().cast::<XmlUtf8Decoder>())
    };
    unsafe { xml_skip_whitespace(reader_slot) };
    unsafe { xml_skip_whitespace(reader_slot) };
    let codepoint = unsafe { xml_decode_skip_whitespace(reader_slot) };
    unsafe {
        xml_reader_restore_position(
            reader_slot.read().cast::<XmlUtf8Decoder>(), (position as i32) as i64, 0,
        )
    };
    codepoint
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::xml_decode_codepoint_and_reset::{
        XmlCodepointDecoderOps, XML_CODEPOINT_DECODER_OPS,
        DEFAULT_XML_CODEPOINT_DECODER_OPS, XML_CODEPOINT_DECODER_OPS_LOCK,
    };
    use super::super::xml_reader_position_before_current::{
        XmlReaderPositionOps, XML_READER_POSITION_OPS, DEFAULT_XML_READER_POSITION_OPS,
    };
    use super::super::xml_reader_restore_position::{
        XmlReaderSeekOps, XML_READER_SEEK_OPS, DEFAULT_XML_READER_SEEK_OPS,
    };

    #[repr(C)]
    struct Reader {
        decoder: XmlUtf8Decoder,
        input: &'static [u32],
        cursor: usize,
        base: i32,
        restored: Option<(i64, u32)>,
    }

    unsafe extern "C" fn decode(reader: *mut XmlUtf8Decoder) -> u32 {
        let reader = unsafe { &mut *reader.cast::<Reader>() };
        if reader.decoder.state == 100 {
            return reader.decoder.codepoint;
        }
        let codepoint = reader.input.get(reader.cursor).copied().unwrap_or(u32::MAX);
        if codepoint != u32::MAX {
            reader.cursor += 1;
        }
        reader.decoder.state = 100;
        reader.decoder.codepoint = codepoint;
        codepoint
    }

    unsafe extern "C" fn position(reader: *mut XmlUtf8Decoder) -> u32 {
        let reader = unsafe { &*reader.cast::<Reader>() };
        (reader.base as u32).wrapping_add(reader.cursor as u32)
    }

    unsafe extern "C" fn seek(reader: *mut XmlUtf8Decoder, position: i64, origin: u32) -> u32 {
        let reader = unsafe { &mut *reader.cast::<Reader>() };
        assert_eq!(reader.decoder.state, 0);
        reader.restored = Some((position, origin));
        reader.cursor = (position - reader.base as i64) as usize;
        // Failure must not replace the looked-ahead codepoint.
        0xffff_ffff
    }

    fn check(input: &'static [u32], base: i32, expected: u32) {
        let _guard = XML_CODEPOINT_DECODER_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            XML_CODEPOINT_DECODER_OPS = XmlCodepointDecoderOps { decode_codepoint: decode };
            XML_READER_POSITION_OPS = XmlReaderPositionOps { position };
            XML_READER_SEEK_OPS = XmlReaderSeekOps { seek };
        }
        let mut reader = Reader {
            decoder: XmlUtf8Decoder { callback_table: 0, state: 100, codepoint: input[0] },
            input, cursor: 1, base, restored: None,
        };
        let mut slot = core::ptr::addr_of_mut!(reader.decoder).cast::<u8>();
        let result = unsafe { xml_peek_second_skip_whitespace(&mut slot) };
        unsafe {
            XML_CODEPOINT_DECODER_OPS = DEFAULT_XML_CODEPOINT_DECODER_OPS;
            XML_READER_POSITION_OPS = DEFAULT_XML_READER_POSITION_OPS;
            XML_READER_SEEK_OPS = DEFAULT_XML_READER_SEEK_OPS;
        }
        assert_eq!(result, expected);
        assert_eq!(reader.restored, Some((base as i64, 0)));
        assert_eq!(reader.cursor, 0);
        assert_eq!(reader.decoder.state, 0);
    }

    #[test]
    fn looks_past_markup_and_xml_whitespace_then_rewinds_negative_position() {
        check(&[0x3c, 0x20, 9, 0x21, 13, 10, 0x5b], -4, 0x5b);
    }

    #[test]
    fn returns_eof_after_one_or_two_codepoints_and_still_rewinds() {
        check(&[0x3c], 0x1234_5678, u32::MAX);
        check(&[0x3c, 0x21], 0, u32::MAX);
    }

    #[test]
    fn does_not_treat_non_xml_space_as_whitespace() {
        check(&[0x3c, 0xa0, 0x3e], i32::MIN, 0x3e);
    }
}
