//! `xml_reader_position_before_current` — `FUN_0825d4e0` @ `0x0825d4e0`.
//! **160 bytes**, `0x0825d4e0..0x0825d57f`; next function: `0x0825d580`.
//! Two verified inbound BL calls (0x0825d390, 0x0825d3dc), both plain,
//! zero predicated; the body has no direct BL and one indirect `blx r1`.
//!
//! Calls vtable +0x0c to obtain the input position, then reads decoder state
//! and subtracts its consumed byte count: states 1/2/4 => 1, 3/5 => 2,
//! 6 => 3, 100 => the encoded codepoint width, other states => 0.
//! The ASCII check is unsigned; subsequent width thresholds are signed,
//! so high-bit codepoints subtract two. Subtraction wraps at 32 bits.
//! Deliberate deviation: host builds use a volatile callback seam for the
//! unidentified virtual method; target dispatch reads the actual vtable word.
//! No NULL checks, Unicode validation, or state reset are added.

use super::xml_decode_codepoint_and_reset::XmlUtf8Decoder;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct XmlReaderPositionOps {
    pub position: unsafe extern "C" fn(*mut XmlUtf8Decoder) -> u32,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_position(_reader: *mut XmlUtf8Decoder) -> u32 {
    panic!("xml_reader_position_before_current requires a virtual position seam on host")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_XML_READER_POSITION_OPS: XmlReaderPositionOps = XmlReaderPositionOps { position: missing_position };

/// Host dispatch for the opaque vtable +0x0c method.
#[cfg(not(target_os = "none"))]
pub static mut XML_READER_POSITION_OPS: XmlReaderPositionOps = DEFAULT_XML_READER_POSITION_OPS;

/// Return the position preceding the active codepoint, using post-callback state.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn xml_reader_position_before_current(reader: *mut XmlUtf8Decoder) -> u32 {
    #[cfg(target_os = "none")]
    let position: unsafe extern "C" fn(*mut XmlUtf8Decoder) -> u32 = unsafe {
        let table = (*reader).callback_table as *const u32;
        core::mem::transmute(table.add(3).read())
    };
    #[cfg(not(target_os = "none"))]
    let position = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(XML_READER_POSITION_OPS)).position
    };
    let position = unsafe { position(reader) };
    let width = match unsafe { (*reader).state } {
        1 | 2 | 4 => 1,
        3 | 5 => 2,
        6 => 3,
        100 => {
            let codepoint = unsafe { (*reader).codepoint };
            if codepoint < 0x80 { 1 }
            else if (codepoint as i32) < 0x800 { 2 }
            else if (codepoint as i32) < 0x10000 { 3 }
            else if (codepoint as i32) < 0x110000 { 4 }
            else { 0 }
        }
        _ => 0,
    };
    position.wrapping_sub(width)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::xml_decode_codepoint_and_reset::XML_CODEPOINT_DECODER_OPS_LOCK;

    unsafe extern "C" fn zero_position(_reader: *mut XmlUtf8Decoder) -> u32 { 0 }

    #[test]
    fn state_widths_and_signed_codepoint_boundaries_wrap() {
        let _guard = XML_CODEPOINT_DECODER_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { XML_READER_POSITION_OPS = XmlReaderPositionOps { position: zero_position } };
        for (state, codepoint, width) in [
            (0, 0, 0u32), (1, 0, 1), (2, 0, 1), (3, 0, 2),
            (4, 0, 1), (5, 0, 2), (6, 0, 3), (7, 0, 0),
            (99, 0, 0), (101, 0, 0), (u32::MAX, 0, 0),
            (100, 0, 1), (100, 0x7f, 1), (100, 0x80, 2),
            (100, 0x7ff, 2), (100, 0x800, 3), (100, 0xd800, 3),
            (100, 0xffff, 3), (100, 0x10000, 4), (100, 0x10ffff, 4),
            (100, 0x110000, 0), (100, 0x7fffffff, 0),
            (100, 0x80000000, 2), (100, u32::MAX, 2),
        ] {
            let mut reader = XmlUtf8Decoder { callback_table: 0, state, codepoint };
            assert_eq!(unsafe { xml_reader_position_before_current(&mut reader) }, 0u32.wrapping_sub(width));
            assert_eq!((reader.state, reader.codepoint), (state, codepoint));
        }
        unsafe { XML_READER_POSITION_OPS = DEFAULT_XML_READER_POSITION_OPS };
    }

    unsafe extern "C" fn mutate_position(reader: *mut XmlUtf8Decoder) -> u32 {
        unsafe { (*reader).state = 100; (*reader).codepoint = 0x10000; }
        123
    }

    #[test]
    fn adjusts_using_state_and_codepoint_after_virtual_call() {
        let _guard = XML_CODEPOINT_DECODER_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { XML_READER_POSITION_OPS = XmlReaderPositionOps { position: mutate_position } };
        let mut reader = XmlUtf8Decoder { callback_table: 0, state: 1, codepoint: 0 };
        assert_eq!(unsafe { xml_reader_position_before_current(&mut reader) }, 119);
        assert_eq!((reader.state, reader.codepoint), (100, 0x10000));
        unsafe { XML_READER_POSITION_OPS = DEFAULT_XML_READER_POSITION_OPS };
    }
}
