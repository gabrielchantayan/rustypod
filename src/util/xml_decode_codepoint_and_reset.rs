//! `xml_decode_codepoint_and_reset` — original: `FUN_0825d7c4` @ `0x0825d7c4`
//! (**24 bytes**, `0x0825d7c4..0x0825d7db`; extent verified against the
//! following initializer at `0x0825d7dc`).
//!
//! Calls the UTF-8 decoder at `0x0825d5dc`, preserves its codepoint or
//! `0xffff_ffff` error/EOF return value, and then clears the decoder's state
//! word. Raw ARM has 11 verified static `bl` call sites, all unconditional.
//! `FUN_0825d5dc` is not yet ported, so the target build calls its verified
//! firmware address while host tests install a decoder seam; this is the sole
//! deliberate deviation.

/// The first three 32-bit words of the UTF-8 decoder object consumed here.
///
/// `callback_table` is deliberately a target-sized word, rather than a host
/// pointer: retailOS invokes its byte callback through this table at `+0` and
/// stores the state cleared by this function at `+4`.
#[repr(C)]
pub struct XmlUtf8Decoder {
    pub callback_table: u32,
    pub state: u32,
    pub codepoint: u32,
}

/// The only direct retailOS callee needed by
/// [`xml_decode_codepoint_and_reset`].
#[derive(Clone, Copy)]
pub struct XmlCodepointDecoderOps {
    /// `FUN_0825d5dc`: decodes a codepoint from the stateful reader.
    pub decode_codepoint: unsafe extern "C" fn(*mut XmlUtf8Decoder) -> u32,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_decode_codepoint(reader: *mut XmlUtf8Decoder) -> u32 {
    let decode: unsafe extern "C" fn(*mut XmlUtf8Decoder) -> u32 =
        unsafe { core::mem::transmute(0x0825_d5dcusize) };
    unsafe { decode(reader) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_decode_codepoint(_reader: *mut XmlUtf8Decoder) -> u32 {
    panic!("xml_decode_codepoint_and_reset requires a decoder seam on host")
}

#[cfg(target_os = "none")]
pub const DEFAULT_XML_CODEPOINT_DECODER_OPS: XmlCodepointDecoderOps = XmlCodepointDecoderOps {
    decode_codepoint: firmware_decode_codepoint,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_XML_CODEPOINT_DECODER_OPS: XmlCodepointDecoderOps = XmlCodepointDecoderOps {
    decode_codepoint: missing_decode_codepoint,
};

/// Volatile seam for the unported UTF-8 decoder.
pub static mut XML_CODEPOINT_DECODER_OPS: XmlCodepointDecoderOps = DEFAULT_XML_CODEPOINT_DECODER_OPS;

#[inline(always)]
unsafe fn ops() -> XmlCodepointDecoderOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(XML_CODEPOINT_DECODER_OPS)) }
}

/// `xml_decode_codepoint_and_reset` — original: `FUN_0825d7c4` @ `0x0825d7c4`
/// (24 bytes; 11 binary-verified unconditional `bl` call sites).
///
/// It deliberately does not guard `reader`: both the firmware decoder call and
/// the following aligned state-word store dereference it. The return value is
/// left intact across the store, exactly as the ARM leaves `r0` unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn xml_decode_codepoint_and_reset(reader: *mut XmlUtf8Decoder) -> u32 {
    let codepoint = unsafe { (ops().decode_codepoint)(reader) };
    unsafe { (*reader).state = 0 };
    codepoint
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut RETURN_VALUE: u32 = 0;
    static mut SEEN_READER: *mut XmlUtf8Decoder = ptr::null_mut();

    unsafe extern "C" fn controlled_decode(reader: *mut XmlUtf8Decoder) -> u32 {
        unsafe {
            ptr::addr_of_mut!(SEEN_READER).write_volatile(reader);
            ptr::addr_of!(RETURN_VALUE).read_volatile()
        }
    }

    fn install(return_value: u32) -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            XML_CODEPOINT_DECODER_OPS = XmlCodepointDecoderOps {
                decode_codepoint: controlled_decode,
            };
            RETURN_VALUE = return_value;
            SEEN_READER = ptr::null_mut();
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            XML_CODEPOINT_DECODER_OPS = DEFAULT_XML_CODEPOINT_DECODER_OPS;
            RETURN_VALUE = 0;
            SEEN_READER = ptr::null_mut();
        }
        drop(guard);
    }

    #[test]
    fn clears_nonzero_state_after_returning_ascii_codepoint() {
        let guard = install(b'<' as u32);
        let mut reader = XmlUtf8Decoder {
            callback_table: 0x1234_5678,
            state: 6,
            codepoint: 0x0010_ffff,
        };
        let reader_ptr = ptr::addr_of_mut!(reader);
        unsafe {
            assert_eq!(xml_decode_codepoint_and_reset(reader_ptr), b'<' as u32);
            assert_eq!(reader.state, 0);
            assert_eq!(reader.codepoint, 0x0010_ffff);
            assert_eq!(ptr::addr_of!(SEEN_READER).read_volatile(), reader_ptr);
        }
        restore(guard);
    }

    #[test]
    fn clears_partial_multibyte_state_after_decoder_error() {
        let guard = install(u32::MAX);
        let mut reader = XmlUtf8Decoder {
            callback_table: 0,
            state: 4,
            codepoint: 0x001f_0000,
        };
        unsafe {
            assert_eq!(xml_decode_codepoint_and_reset(ptr::addr_of_mut!(reader)), u32::MAX);
            assert_eq!(reader.state, 0);
            assert_eq!(reader.codepoint, 0x001f_0000);
        }
        restore(guard);
    }
}
