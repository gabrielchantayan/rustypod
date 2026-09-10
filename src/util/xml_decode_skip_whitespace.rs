//! `xml_decode_skip_whitespace` — original: `FUN_0825d318` @ `0x0825d318`
//! (**60 bytes**, `0x0825d318..0x0825d353`; extent verified against
//! `FUN_0825d354` at `0x0825d354`).
//!
//! Decodes one XML UTF-8 codepoint without resetting the decoder state, then
//! discards XML whitespace (`U+0020`, `U+0009`, `U+000D`, `U+000A`). The
//! initial non-space codepoint leaves the state as the raw decode left it;
//! every whitespace result and its successor are decoded through the reset
//! wrapper. The `u32::MAX` error/EOF sentinel is classified and returned.
//! Raw ARM has 10 verified static `bl` call sites, all unconditional.
//!
//! `FUN_0825d5dc` and `FUN_0825d2fc` remain unported. Target builds reach
//! their fixed firmware addresses through the existing volatile seams; host
//! tests install callbacks. This is the sole deliberate deviation.

use super::xml_decode_codepoint_and_reset::{
    xml_decode_codepoint_and_reset, XmlCodepointDecoderOps, XmlUtf8Decoder,
    XML_CODEPOINT_DECODER_OPS,
};
use super::xml_skip_whitespace::{XmlWhitespaceOps, XML_WHITESPACE_OPS};

#[inline(always)]
unsafe fn decoder_ops() -> XmlCodepointDecoderOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(XML_CODEPOINT_DECODER_OPS)) }
}

#[inline(always)]
unsafe fn whitespace_ops() -> XmlWhitespaceOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(XML_WHITESPACE_OPS)) }
}

/// `xml_decode_skip_whitespace` — original: `FUN_0825d318` @ `0x0825d318`
/// (60 bytes; 10 binary-verified unconditional `bl` call sites).
///
/// The initial decode deliberately does not reset `reader.state`. Only after
/// classifying an XML whitespace codepoint does the loop use the reset wrapper
/// for its next decode. The `reader_slot` and duplicated codepoint arguments
/// to the predicate exactly match the ARM register setup.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn xml_decode_skip_whitespace(reader_slot: *mut *mut u8) -> u32 {
    let mut codepoint = unsafe {
        (decoder_ops().decode_codepoint)(reader_slot.read().cast::<XmlUtf8Decoder>())
    };
    loop {
        if unsafe { (whitespace_ops().is_xml_whitespace)(reader_slot, codepoint, codepoint) } == 0 {
            return codepoint;
        }
        codepoint = unsafe {
            xml_decode_codepoint_and_reset(reader_slot.read().cast::<XmlUtf8Decoder>())
        };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use super::super::xml_decode_codepoint_and_reset::{
        DEFAULT_XML_CODEPOINT_DECODER_OPS, XML_CODEPOINT_DECODER_OPS_LOCK,
    };
    use super::super::xml_skip_whitespace::DEFAULT_XML_WHITESPACE_OPS;
    use core::ptr;
    use std::sync::MutexGuard;
    use std::vec::Vec;

    static mut DECODED: Vec<u32> = Vec::new();
    static mut DECODE_INDEX: usize = 0;
    static mut PREDICATE_CALLS: Vec<(*mut *mut u8, u32, u32)> = Vec::new();

    unsafe extern "C" fn queued_decode(reader: *mut XmlUtf8Decoder) -> u32 {
        let index = unsafe { ptr::addr_of!(DECODE_INDEX).read_volatile() };
        let value = unsafe { (&*ptr::addr_of!(DECODED))[index] };
        unsafe {
            ptr::addr_of_mut!(DECODE_INDEX).write_volatile(index + 1);
            (*reader).state = (*reader).state.wrapping_add(1);
        }
        value
    }

    unsafe extern "C" fn xml_whitespace_predicate(
        reader_slot: *mut *mut u8,
        codepoint: u32,
        duplicate_codepoint: u32,
    ) -> u32 {
        unsafe {
            (*ptr::addr_of_mut!(PREDICATE_CALLS)).push((reader_slot, codepoint, duplicate_codepoint));
        }
        u32::from(matches!(codepoint, 0x20 | 0x09 | 0x0d | 0x0a))
    }

    fn install(decoded: &[u32]) -> MutexGuard<'static, ()> {
        let guard = XML_CODEPOINT_DECODER_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            XML_CODEPOINT_DECODER_OPS = XmlCodepointDecoderOps {
                decode_codepoint: queued_decode,
            };
            XML_WHITESPACE_OPS = XmlWhitespaceOps {
                is_xml_whitespace: xml_whitespace_predicate,
            };
            *ptr::addr_of_mut!(DECODED) = decoded.to_vec();
            DECODE_INDEX = 0;
            (*ptr::addr_of_mut!(PREDICATE_CALLS)).clear();
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            XML_CODEPOINT_DECODER_OPS = DEFAULT_XML_CODEPOINT_DECODER_OPS;
            XML_WHITESPACE_OPS = DEFAULT_XML_WHITESPACE_OPS;
            (*ptr::addr_of_mut!(DECODED)).clear();
            DECODE_INDEX = 0;
            (*ptr::addr_of_mut!(PREDICATE_CALLS)).clear();
        }
        drop(guard);
    }

    #[test]
    fn returns_initial_non_whitespace_without_resetting_state() {
        let guard = install(&[b'<' as u32]);
        let mut reader = XmlUtf8Decoder {
            callback_table: 0,
            state: 6,
            codepoint: 0,
        };
        let mut reader_ptr = ptr::addr_of_mut!(reader).cast::<u8>();
        let reader_slot = ptr::addr_of_mut!(reader_ptr);
        unsafe {
            assert_eq!(xml_decode_skip_whitespace(reader_slot), b'<' as u32);
            assert_eq!(reader.state, 7);
            assert_eq!(ptr::addr_of!(DECODE_INDEX).read_volatile(), 1);
            assert_eq!((*ptr::addr_of!(PREDICATE_CALLS)).as_slice(), &[(reader_slot, b'<' as u32, b'<' as u32)]);
        }
        restore(guard);
    }

    #[test]
    fn resets_after_whitespace_and_preserves_terminal_codepoint_state() {
        let guard = install(&[0x20, 0x09, b'X' as u32]);
        let mut reader = XmlUtf8Decoder {
            callback_table: 0,
            state: 3,
            codepoint: 0,
        };
        let mut reader_ptr = ptr::addr_of_mut!(reader).cast::<u8>();
        let reader_slot = ptr::addr_of_mut!(reader_ptr);
        unsafe {
            assert_eq!(xml_decode_skip_whitespace(reader_slot), b'X' as u32);
            assert_eq!(reader.state, 0);
            assert_eq!(ptr::addr_of!(DECODE_INDEX).read_volatile(), 3);
            assert_eq!(
                (*ptr::addr_of!(PREDICATE_CALLS)).as_slice(),
                &[
                    (reader_slot, 0x20, 0x20),
                    (reader_slot, 0x09, 0x09),
                    (reader_slot, b'X' as u32, b'X' as u32),
                ]
            );
        }
        restore(guard);
    }

    #[test]
    fn returns_eof_sentinel_after_classification_without_extra_decode() {
        let guard = install(&[u32::MAX]);
        let mut reader = XmlUtf8Decoder {
            callback_table: 0,
            state: 0,
            codepoint: 0,
        };
        let mut reader_ptr = ptr::addr_of_mut!(reader).cast::<u8>();
        let reader_slot = ptr::addr_of_mut!(reader_ptr);
        unsafe {
            assert_eq!(xml_decode_skip_whitespace(reader_slot), u32::MAX);
            assert_eq!(reader.state, 1);
            assert_eq!(ptr::addr_of!(DECODE_INDEX).read_volatile(), 1);
        }
        restore(guard);
    }
}
