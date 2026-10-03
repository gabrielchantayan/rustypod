//! `xml_reader_restore_position` — `FUN_0825d580` @ `0x0825d580`.
//! **44 bytes**, `0x0825d580..0x0825d5ab`; next real prologue: `0x0825d5ac`.
//! Two verified static BL references, both unconditional (0x0825d3c4 and
//! 0x0825d418), no predicated BL references; the body has one `blx r1`.
//!
//! Clears the decoder state before calling its vtable +0x10 method, forwarding
//! the signed 64-bit position in r2:r3 and the stack origin word, and returning
//! the method's r0 unchanged. r1 is overwritten with the method address and is
//! ABI padding, not an origin argument. No NULL checks are added.
//! Deliberate deviation: host builds use the existing volatile callback-seam
//! convention for the unidentified virtual method; target builds use its actual
//! vtable word. The semantic i64 argument preserves ARM's even-register alignment.

use super::xml_decode_codepoint_and_reset::XmlUtf8Decoder;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct XmlReaderSeekOps {
    pub seek: unsafe extern "C" fn(*mut XmlUtf8Decoder, i64, u32) -> u32,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_seek(_reader: *mut XmlUtf8Decoder, _position: i64, _origin: u32) -> u32 {
    panic!("xml_reader_restore_position requires a virtual seek seam on host")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_XML_READER_SEEK_OPS: XmlReaderSeekOps = XmlReaderSeekOps { seek: missing_seek };

/// Host dispatch for the opaque vtable +0x10 method, not a firmware-address seam.
#[cfg(not(target_os = "none"))]
pub static mut XML_READER_SEEK_OPS: XmlReaderSeekOps = DEFAULT_XML_READER_SEEK_OPS;

/// Clear state, then seek; preserve the virtual method's result and mutations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn xml_reader_restore_position(
    reader: *mut XmlUtf8Decoder,
    position: i64,
    origin: u32,
) -> u32 {
    unsafe { (*reader).state = 0 };
    #[cfg(target_os = "none")]
    let seek: unsafe extern "C" fn(*mut XmlUtf8Decoder, i64, u32) -> u32 = unsafe {
        let table = (*reader).callback_table as *const u32;
        core::mem::transmute(table.add(4).read())
    };
    #[cfg(not(target_os = "none"))]
    let seek = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(XML_READER_SEEK_OPS)).seek
    };
    unsafe { seek(reader, position, origin) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::xml_decode_codepoint_and_reset::XML_CODEPOINT_DECODER_OPS_LOCK;

    unsafe extern "C" fn bounded_seek(reader: *mut XmlUtf8Decoder, position: i64, origin: u32) -> u32 {
        assert_eq!(unsafe { (*reader).state }, 0);
        assert_eq!(unsafe { (*reader).codepoint }, 0x1234);
        let result = if origin == 0 && (0..=0xffff_ffff).contains(&position) { 0 } else { u32::MAX };
        unsafe { (*reader).state = 7 };
        result
    }

    #[test]
    fn clears_state_before_seek_and_preserves_errors_and_seek_mutations() {
        let _guard = XML_CODEPOINT_DECODER_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { XML_READER_SEEK_OPS = XmlReaderSeekOps { seek: bounded_seek } };
        for (position, origin, expected) in [
            (0, 0, 0), (0xffff_ffff, 0, 0), (-1, 0, u32::MAX),
            (0x1_0000_0000, 0, u32::MAX), (i64::MIN, 0, u32::MAX),
            (i64::MAX, 0, u32::MAX), (0, 2, u32::MAX),
        ] {
            let mut reader = XmlUtf8Decoder { callback_table: 0, state: u32::MAX, codepoint: 0x1234 };
            assert_eq!(unsafe { xml_reader_restore_position(&mut reader, position, origin) }, expected);
            assert_eq!(reader.state, 7);
            assert_eq!(reader.codepoint, 0x1234);
        }
        unsafe { XML_READER_SEEK_OPS = DEFAULT_XML_READER_SEEK_OPS };
    }
}
