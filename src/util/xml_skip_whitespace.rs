//! `xml_skip_whitespace` — original: `FUN_0825d354` @ `0x0825d354`
//! (**48 bytes**, `0x0825d354..0x0825d383`; extent verified against the
//! following function at `0x0825d384`).
//!
//! Decodes one XML UTF-8 codepoint at a time and discards XML whitespace
//! (`U+0020`, `U+0009`, `U+000D`, or `U+000A`) until the first other value,
//! including the `u32::MAX` decoder error/EOF sentinel. It has 26 verified
//! static `bl` call sites: 25 unconditional and one `blne` at `0x0825d180`.
//!
//! `FUN_0825d7c4` (decode-and-reset) is now ported as
//! [`super::xml_decode_codepoint_and_reset::xml_decode_codepoint_and_reset`].
//! `FUN_0825d2fc` remains unported, so this port preserves only its target
//! call behind a volatile dispatch seam. Host tests install both required
//! callbacks.

use super::xml_decode_codepoint_and_reset::{
    xml_decode_codepoint_and_reset, XmlUtf8Decoder,
};

/// The one direct retailOS callee still needed by [`xml_skip_whitespace`].
#[derive(Clone, Copy)]
pub struct XmlWhitespaceOps {
    /// `FUN_0825d2fc`: returns nonzero for XML whitespace. The third
    /// argument duplicates the codepoint exactly as the ARM `mov r2,r0`.
    pub is_xml_whitespace: unsafe extern "C" fn(*mut *mut u8, u32, u32) -> u32,
}


#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_is_xml_whitespace(
    reader_slot: *mut *mut u8,
    codepoint: u32,
    duplicate_codepoint: u32,
) -> u32 {
    let predicate: unsafe extern "C" fn(*mut *mut u8, u32, u32) -> u32 =
        unsafe { core::mem::transmute(0x0825_d2fcusize) };
    unsafe { predicate(reader_slot, codepoint, duplicate_codepoint) }
}


#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_is_xml_whitespace(
    _reader_slot: *mut *mut u8,
    _codepoint: u32,
    _duplicate_codepoint: u32,
) -> u32 {
    panic!("xml_skip_whitespace requires a whitespace predicate seam on host")
}

#[cfg(target_os = "none")]
pub const DEFAULT_XML_WHITESPACE_OPS: XmlWhitespaceOps = XmlWhitespaceOps {
    is_xml_whitespace: firmware_is_xml_whitespace,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_XML_WHITESPACE_OPS: XmlWhitespaceOps = XmlWhitespaceOps {
    is_xml_whitespace: missing_is_xml_whitespace,
};

/// Volatile seam for the remaining unported XML whitespace predicate.
pub static mut XML_WHITESPACE_OPS: XmlWhitespaceOps = DEFAULT_XML_WHITESPACE_OPS;

#[inline(always)]
unsafe fn ops() -> XmlWhitespaceOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(XML_WHITESPACE_OPS)) }
}

/// `xml_skip_whitespace` — original: `FUN_0825d354` @ `0x0825d354`
/// (48 bytes; 26 binary-verified static `bl` call sites).
///
/// Dereferences `reader_slot` without a NULL check, then repeatedly decodes
/// and classifies codepoints. The first codepoint whose predicate result is
/// zero is returned unchanged. Any nonzero predicate result continues the
/// loop, matching the ARM `cmp r0,#0; bne` rather than assuming a normalized
/// boolean result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn xml_skip_whitespace(reader_slot: *mut *mut u8) -> u32 {
    loop {
        let codepoint = unsafe {
            xml_decode_codepoint_and_reset(reader_slot.read().cast::<XmlUtf8Decoder>())
        };
        if unsafe { (ops().is_xml_whitespace)(reader_slot, codepoint, codepoint) } == 0 {
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
        XML_CODEPOINT_DECODER_OPS,
    };
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut DECODED: Vec<u32> = Vec::new();
    static mut DECODE_INDEX: usize = 0;
    static mut PREDICATE_CALLS: Vec<(*mut *mut u8, u32, u32)> = Vec::new();

    unsafe extern "C" fn queued_next_codepoint(_reader: *mut XmlUtf8Decoder) -> u32 {
        let index = unsafe { ptr::addr_of!(DECODE_INDEX).read_volatile() };
        let value = unsafe { (&*ptr::addr_of!(DECODED))[index] };
        unsafe { ptr::addr_of_mut!(DECODE_INDEX).write_volatile(index + 1) };
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
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            XML_CODEPOINT_DECODER_OPS = XmlCodepointDecoderOps {
                decode_codepoint: queued_next_codepoint,
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
            assert_eq!((*ptr::addr_of!(PREDICATE_CALLS)).as_slice(), &[(reader_slot, b'<' as u32, b'<' as u32)]);
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
            let calls = &*ptr::addr_of!(PREDICATE_CALLS);
            assert_eq!(calls.len(), 5);
            assert!(calls.iter().all(|(seen_slot, _, _)| *seen_slot == reader_slot));
            assert!(calls.iter().all(|(_, codepoint, duplicate)| codepoint == duplicate));
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
            assert_eq!((*ptr::addr_of!(PREDICATE_CALLS)).as_slice(), &[(reader_slot, u32::MAX, u32::MAX)]);
        }
        restore(guard);
    }
}
