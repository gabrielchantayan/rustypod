//! `xml_peek_skip_whitespace` — original: `FUN_0825d384` @ `0x0825d384`
//! (**76 bytes**, `0x0825d384..0x0825d3cf`; extent verified against
//! `FUN_0825d3d0` at `0x0825d3d0`).
//!
//! Saves the input position at the start of the decoder's active codepoint,
//! runs the reset and raw whitespace-skipping decoders, then restores that
//! position and returns the raw helper's codepoint. Raw ARM has 6 verified
//! static `bl` call sites, all unconditional.
//!
//! `FUN_0825d4e0` (position adjustment) and `FUN_0825d580` (reader reset and
//! seek) remain unported. Target builds reach their fixed firmware addresses
//! through volatile dispatch seams; host tests install callbacks. This is the
//! sole deliberate deviation.

use super::xml_decode_codepoint_and_reset::XmlUtf8Decoder;
use super::xml_decode_skip_whitespace::xml_decode_skip_whitespace;
use super::xml_skip_whitespace::xml_skip_whitespace;

/// The two direct retailOS callees needed by [`xml_peek_skip_whitespace`].
#[derive(Clone, Copy)]
pub struct XmlPeekOps {
    /// `FUN_0825d4e0`: reports the input position before the active codepoint.
    pub position_before_current: unsafe extern "C" fn(*mut XmlUtf8Decoder) -> u32,
    /// `FUN_0825d580`: clears decoder state and restores a signed input position.
    pub restore_position: unsafe extern "C" fn(*mut XmlUtf8Decoder, u32, u32, u32, u32),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_position_before_current(reader: *mut XmlUtf8Decoder) -> u32 {
    let position_before_current: unsafe extern "C" fn(*mut XmlUtf8Decoder) -> u32 =
        unsafe { core::mem::transmute(0x0825_d4e0usize) };
    unsafe { position_before_current(reader) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_position_before_current(_reader: *mut XmlUtf8Decoder) -> u32 {
    panic!("xml_peek_skip_whitespace requires a position seam on host")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_restore_position(
    reader: *mut XmlUtf8Decoder,
    origin: u32,
    position: u32,
    position_sign: u32,
    trailing_zero: u32,
) {
    let restore_position: unsafe extern "C" fn(*mut XmlUtf8Decoder, u32, u32, u32, u32) =
        unsafe { core::mem::transmute(0x0825_d580usize) };
    unsafe { restore_position(reader, origin, position, position_sign, trailing_zero) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_restore_position(
    _reader: *mut XmlUtf8Decoder,
    _origin: u32,
    _position: u32,
    _position_sign: u32,
    _trailing_zero: u32,
) {
    panic!("xml_peek_skip_whitespace requires a restore seam on host")
}

#[cfg(target_os = "none")]
pub const DEFAULT_XML_PEEK_OPS: XmlPeekOps = XmlPeekOps {
    position_before_current: firmware_position_before_current,
    restore_position: firmware_restore_position,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_XML_PEEK_OPS: XmlPeekOps = XmlPeekOps {
    position_before_current: missing_position_before_current,
    restore_position: missing_restore_position,
};

/// Volatile seams for the unported reader position helpers.
pub static mut XML_PEEK_OPS: XmlPeekOps = DEFAULT_XML_PEEK_OPS;

#[inline(always)]
unsafe fn ops() -> XmlPeekOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(XML_PEEK_OPS)) }
}

/// `xml_peek_skip_whitespace` — original: `FUN_0825d384` @ `0x0825d384`
/// (76 bytes; 6 binary-verified unconditional `bl` call sites).
///
/// The first whitespace helper's result is deliberately discarded. The
/// position is sign-extended exactly as `asr r1, r6, #31` does, and the reset
/// helper receives the literal zero values in its second and fifth arguments.
/// Like the ARM, this function dereferences `reader_slot` without a NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn xml_peek_skip_whitespace(reader_slot: *mut *mut u8) -> u32 {
    let reader = unsafe { reader_slot.read().cast::<XmlUtf8Decoder>() };
    let position = unsafe { (ops().position_before_current)(reader) };
    unsafe { xml_skip_whitespace(reader_slot) };
    let codepoint = unsafe { xml_decode_skip_whitespace(reader_slot) };
    let position_sign = ((position as i32) >> 31) as u32;
    unsafe { (ops().restore_position)(reader, 0, position, position_sign, 0) };
    codepoint
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use super::super::xml_decode_codepoint_and_reset::{
        XmlCodepointDecoderOps, DEFAULT_XML_CODEPOINT_DECODER_OPS,
        XML_CODEPOINT_DECODER_OPS, XML_CODEPOINT_DECODER_OPS_LOCK,
    };
    use core::ptr;
    use std::sync::MutexGuard;

    static mut DECODED: [u32; 3] = [0; 3];
    static mut DECODE_INDEX: usize = 0;
    static mut POSITION: u32 = 0;
    static mut POSITION_CALLS: usize = 0;
    static mut RESTORE_CALL: Option<(*mut XmlUtf8Decoder, u32, u32, u32, u32)> = None;

    unsafe extern "C" fn queued_next_codepoint(_reader: *mut XmlUtf8Decoder) -> u32 {
        let index = unsafe { ptr::addr_of!(DECODE_INDEX).read_volatile() };
        let decoded = unsafe { ptr::addr_of!(DECODED).read_volatile() };
        unsafe { ptr::addr_of_mut!(DECODE_INDEX).write_volatile(index + 1) };
        decoded[index]
    }


    unsafe extern "C" fn position_before_current(_reader: *mut XmlUtf8Decoder) -> u32 {
        let calls = unsafe { ptr::addr_of!(POSITION_CALLS).read_volatile() };
        unsafe { ptr::addr_of_mut!(POSITION_CALLS).write_volatile(calls + 1) };
        unsafe { ptr::addr_of!(POSITION).read_volatile() }
    }

    unsafe extern "C" fn restore_position(
        reader: *mut XmlUtf8Decoder,
        origin: u32,
        position: u32,
        position_sign: u32,
        trailing_zero: u32,
    ) {
        unsafe {
            (*reader).state = 0;
            ptr::addr_of_mut!(RESTORE_CALL).write_volatile(Some((
                reader,
                origin,
                position,
                position_sign,
                trailing_zero,
            )));
        }
    }

    fn install(decoded: &[u32], position: u32) -> MutexGuard<'static, ()> {
        let guard = XML_CODEPOINT_DECODER_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        assert!(decoded.len() <= 3);
        let mut queued = [0; 3];
        queued[..decoded.len()].copy_from_slice(decoded);
        unsafe {
            XML_CODEPOINT_DECODER_OPS = XmlCodepointDecoderOps {
                decode_codepoint: queued_next_codepoint,
            };
            XML_PEEK_OPS = XmlPeekOps {
                position_before_current,
                restore_position,
            };
            ptr::addr_of_mut!(DECODED).write_volatile(queued);
            ptr::addr_of_mut!(DECODE_INDEX).write_volatile(0);
            ptr::addr_of_mut!(POSITION).write_volatile(position);
            ptr::addr_of_mut!(POSITION_CALLS).write_volatile(0);
            ptr::addr_of_mut!(RESTORE_CALL).write_volatile(None);
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            XML_CODEPOINT_DECODER_OPS = DEFAULT_XML_CODEPOINT_DECODER_OPS;
            XML_PEEK_OPS = DEFAULT_XML_PEEK_OPS;
            ptr::addr_of_mut!(DECODED).write_volatile([0; 3]);
            ptr::addr_of_mut!(DECODE_INDEX).write_volatile(0);
            ptr::addr_of_mut!(POSITION).write_volatile(0);
            ptr::addr_of_mut!(POSITION_CALLS).write_volatile(0);
            ptr::addr_of_mut!(RESTORE_CALL).write_volatile(None);
        }
        drop(guard);
    }
    #[test]
    fn peeks_after_xml_whitespace_and_restores_a_negative_position() {
        let guard = install(&[0x20, b'!' as u32, b'[' as u32], 0xffff_fffc);
        let mut decoder = XmlUtf8Decoder {
            callback_table: 0,
            state: 7,
            codepoint: 0,
        };
        let mut reader = ptr::addr_of_mut!(decoder).cast::<u8>();
        let reader_slot = ptr::addr_of_mut!(reader);
        unsafe {
            assert_eq!(xml_peek_skip_whitespace(reader_slot), b'[' as u32);
            assert_eq!(ptr::addr_of!(DECODE_INDEX).read_volatile(), 3);
            assert_eq!(ptr::addr_of!(POSITION_CALLS).read_volatile(), 1);
            assert_eq!(
                ptr::addr_of!(RESTORE_CALL).read_volatile(),
                Some((
                    ptr::addr_of_mut!(decoder),
                    0,
                    0xffff_fffc,
                    u32::MAX,
                    0,
                )),
            );
            assert_eq!(decoder.state, 0);
        }
        restore(guard);
    }

    #[test]
    fn returns_the_decoder_eof_sentinel_and_restores_a_positive_position() {
        let guard = install(&[u32::MAX, u32::MAX], 0x1234_5678);
        let mut decoder = XmlUtf8Decoder {
            callback_table: 0,
            state: 4,
            codepoint: 0,
        };
        let mut reader = ptr::addr_of_mut!(decoder).cast::<u8>();
        let reader_slot = ptr::addr_of_mut!(reader);
        unsafe {
            assert_eq!(xml_peek_skip_whitespace(reader_slot), u32::MAX);
            assert_eq!(ptr::addr_of!(DECODE_INDEX).read_volatile(), 2);
            assert_eq!(
                ptr::addr_of!(RESTORE_CALL).read_volatile(),
                Some((ptr::addr_of_mut!(decoder), 0, 0x1234_5678, 0, 0)),
            );
            assert_eq!(decoder.state, 0);
        }
        restore(guard);
    }
}
