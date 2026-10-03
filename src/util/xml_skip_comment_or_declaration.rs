//! `xml_skip_comment_or_declaration` — original: `FUN_0825c9c4` @ `0x0825c9c4`.
//! True extent: 156 bytes, `0x0825c9c4..0x0825ca5f`. Two inbound plain BLs
//! (0x0825cb2c, 0x0825cfb0), zero predicated; nine outbound plain BLs.
//! Consumes `!`, then delegates a leading `D` to the declaration scanner;
//! otherwise consumes the second comment opener and scans for two hyphens
//! followed by a whitespace-skipping peek of `>`. Returns 0x22 on success,
//! 0x38 on input exhaustion. Opening syntax is deliberately not validated.
//! Ghidra's 212-byte extent includes the separate 56-byte helper at 0x0825ca60:
//! the conditional branch restores LR and the entire frame before entering
//! that helper's own prologue. Deliberate deviation: Rust calls that verified
//! firmware helper through a volatile seam rather than reproducing its body.

use super::xml_decode_codepoint_and_reset::{xml_decode_codepoint_and_reset, XmlUtf8Decoder, XML_CODEPOINT_DECODER_OPS};
use super::xml_input_is_exhausted::{xml_input_is_exhausted, XmlInput};
use super::xml_peek_skip_whitespace::xml_peek_skip_whitespace;
use super::xml_skip_whitespace::xml_skip_whitespace;

/// Pointer fields retain their target offsets (+0, +4) on ARM and remain
/// usable native pointers on host. Only this prefix of the parser is accessed.
#[repr(C)]
pub struct XmlMarkupParser {
    pub input: *mut XmlInput,
    pub reader: *mut u8,
}

#[derive(Clone, Copy)]
pub struct XmlDeclarationOps {
    pub skip_declaration: unsafe extern "C" fn(*mut XmlMarkupParser, *mut u8) -> u32,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_skip_declaration(parser: *mut XmlMarkupParser, context: *mut u8) -> u32 {
    let skip: unsafe extern "C" fn(*mut XmlMarkupParser, *mut u8) -> u32 =
        unsafe { core::mem::transmute(0x0825_ca60usize) };
    unsafe { skip(parser, context) }
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_skip_declaration(_parser: *mut XmlMarkupParser, _context: *mut u8) -> u32 {
    panic!("xml_skip_comment_or_declaration requires a declaration seam on host")
}
#[cfg(target_os = "none")]
pub const DEFAULT_XML_DECLARATION_OPS: XmlDeclarationOps = XmlDeclarationOps { skip_declaration: firmware_skip_declaration };
#[cfg(not(target_os = "none"))]
pub const DEFAULT_XML_DECLARATION_OPS: XmlDeclarationOps = XmlDeclarationOps { skip_declaration: missing_skip_declaration };
pub static mut XML_DECLARATION_OPS: XmlDeclarationOps = DEFAULT_XML_DECLARATION_OPS;

/// # Safety
/// `parser` must contain valid input and reader objects; the decoder, reader
/// virtual methods, and declaration helper must satisfy their firmware contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn xml_skip_comment_or_declaration(parser: *mut XmlMarkupParser, context: *mut u8) -> u32 {
    let slot = unsafe { core::ptr::addr_of_mut!((*parser).reader) };
    unsafe { xml_skip_whitespace(slot); }
    if unsafe { xml_decode_codepoint_and_reset((*parser).reader.cast()) } == b'D' as u32 {
        let ops = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(XML_DECLARATION_OPS)) };
        return unsafe { (ops.skip_declaration)(parser, context) };
    }
    unsafe { xml_decode_codepoint_and_reset((*parser).reader.cast()); }
    loop {
        if unsafe { xml_input_is_exhausted((*parser).input) } != 0 {
            return 0x38;
        }
        if unsafe { xml_skip_whitespace(slot) } != b'-' as u32 { continue; }
        let decoder = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(XML_CODEPOINT_DECODER_OPS)) };
        if unsafe { (decoder.decode_codepoint)((*parser).reader.cast::<XmlUtf8Decoder>()) } != b'-' as u32 { continue; }
        if unsafe { xml_peek_skip_whitespace(slot) } != b'>' as u32 { continue; }
        unsafe {
            xml_decode_codepoint_and_reset((*parser).reader.cast());
            xml_skip_whitespace(slot);
        }
        return 0x22;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::xml_decode_codepoint_and_reset::{XmlCodepointDecoderOps, DEFAULT_XML_CODEPOINT_DECODER_OPS, XML_CODEPOINT_DECODER_OPS_LOCK};
    use super::super::xml_input_is_exhausted::{XmlInputOps, XML_INPUT_OPS, DEFAULT_XML_INPUT_OPS};
    use super::super::xml_reader_position_before_current::{XmlReaderPositionOps, XML_READER_POSITION_OPS, DEFAULT_XML_READER_POSITION_OPS};
    use super::super::xml_reader_restore_position::{XmlReaderSeekOps, XML_READER_SEEK_OPS, DEFAULT_XML_READER_SEEK_OPS};

    #[repr(C)]
    struct Reader { decoder: XmlUtf8Decoder, bytes: &'static [u8], position: usize }
    unsafe extern "C" fn decode(reader: *mut XmlUtf8Decoder) -> u32 {
        let r = unsafe { &mut *reader.cast::<Reader>() };
        if r.decoder.state == 0 {
            r.decoder.codepoint = r.bytes.get(r.position).map_or(u32::MAX, |b| *b as u32);
            if r.position < r.bytes.len() { r.position += 1; }
            r.decoder.state = 1;
        }
        r.decoder.codepoint
    }
    unsafe extern "C" fn position(reader: *mut XmlUtf8Decoder) -> u32 {
        unsafe { (*reader.cast::<Reader>()).position as u32 }
    }
    unsafe extern "C" fn seek(reader: *mut XmlUtf8Decoder, position: i64, origin: u32) -> u32 {
        assert_eq!(origin, 0);
        unsafe { (*reader.cast::<Reader>()).position = position as usize; }
        0
    }
    #[repr(C)]
    struct Input { input: XmlInput, reader: *mut Reader }
    unsafe extern "C" fn exhausted(input: *mut XmlInput) -> u32 {
        let r = unsafe { &*(*input.cast::<Input>()).reader };
        u32::from(r.position == r.bytes.len() && r.decoder.state == 0)
    }

    #[test]
    fn comment_terminator_and_exhaustion_boundaries() {
        let _guard = XML_CODEPOINT_DECODER_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            XML_CODEPOINT_DECODER_OPS = XmlCodepointDecoderOps { decode_codepoint: decode };
            XML_INPUT_OPS = XmlInputOps { is_exhausted: exhausted };
            XML_READER_POSITION_OPS = XmlReaderPositionOps { position };
            XML_READER_SEEK_OPS = XmlReaderSeekOps { seek };
        }
        for (bytes, result, consumed) in [
            (&b"!---->rest"[..], 0x22, 6),
            (&b"!--body-- \t>rest"[..], 0x22, 12),
            (&b"!--a-b--x--->rest"[..], 0x22, 13),
            (&b"!--"[..], 0x38, 3),
            (&b"!--body-"[..], 0x38, 8),
            (&b"!--body--x"[..], 0x38, 10),
            (&b"!xy--->rest"[..], 0x22, 7),
        ] {
            let mut reader = Reader { decoder: XmlUtf8Decoder { callback_table: 0, state: 0, codepoint: 0 }, bytes, position: 0 };
            let mut input = Input { input: XmlInput { vtable: 0, status: 0 }, reader: &mut reader };
            let mut parser = XmlMarkupParser { input: &mut input.input, reader: (&mut reader as *mut Reader).cast() };
            assert_eq!(unsafe { xml_skip_comment_or_declaration(&mut parser, core::ptr::null_mut()) }, result, "{bytes:?}");
            assert_eq!(reader.position, consumed, "{bytes:?}");
            assert_eq!(reader.decoder.state, 0, "{bytes:?}");
        }
        unsafe {
            XML_CODEPOINT_DECODER_OPS = DEFAULT_XML_CODEPOINT_DECODER_OPS;
            XML_INPUT_OPS = DEFAULT_XML_INPUT_OPS;
            XML_READER_POSITION_OPS = DEFAULT_XML_READER_POSITION_OPS;
            XML_READER_SEEK_OPS = DEFAULT_XML_READER_SEEK_OPS;
        }
    }
}
