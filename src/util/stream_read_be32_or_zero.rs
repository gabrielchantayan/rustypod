//! Big-endian stream-word reader with a zero-on-failure output —
//! `stream_read_be32_or_zero` @ 0x080575cc.
//!
//! Original: `FUN_080575cc` @ 0x080575cc (36 bytes; raw ARM confirms the
//! next sibling `FUN_080575f0` opens at 0x080575f0). Decoding every B/BL word
//! in osos.dec finds 18 direct call sites, all plain unconditional `bl`.
//!
//! Algorithm: initialize a stack-local u32 to zero; call
//! [`super::stream_read_be32::stream_read_be32`] with that local; unconditionally
//! store the local to `*out`; return the callee's 0/1 status unchanged. Thus a
//! failed read writes zero rather than leaving `*out` untouched, unlike the
//! underlying reader. Deliberate deviations: Rust uses a local `u32` rather
//! than the retail stack slot; both have the same initialized value, call ABI,
//! output store, and return status.

use super::stream_read_be32::stream_read_be32;

/// stream_read_be32_or_zero — original: `FUN_080575cc` @ 0x080575cc (36
/// bytes; 18 unpredicated `bl` call sites, verified by decoding every B/BL
/// word in osos.dec).
///
/// Reads a big-endian u32 through [`stream_read_be32`], always storing to
/// `*out`. A failed read stores zero and returns 0; a successful read stores
/// the decoded word and returns 1. The original has no NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_read_be32_or_zero")]
pub unsafe extern "C" fn stream_read_be32_or_zero(ctx: u32, out: *mut u32) -> i32 {
    let mut value = 0;
    let status = unsafe { stream_read_be32(ctx, &mut value) };
    unsafe { *out = value };
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::STREAM_READ_CORE_TEST_LOCK;
    use crate::util::stream_read_be32::{reset_stream_read_core, STREAM_READ_CORE};

    static mut FILL: [u8; 4] = [0; 4];
    static mut STATUS: i32 = 0;

    unsafe extern "C" fn fake_stream_read_core(
        _ctx: u32,
        buf: *mut u8,
        _len: u32,
        _err_out: *mut u32,
    ) -> i32 {
        unsafe {
            let fill = core::ptr::addr_of!(FILL).read();
            core::ptr::copy_nonoverlapping(fill.as_ptr(), buf, fill.len());
            core::ptr::addr_of!(STATUS).read()
        }
    }

    struct CoreReset;

    impl Drop for CoreReset {
        fn drop(&mut self) {
            unsafe { reset_stream_read_core() };
        }
    }

    fn install_core() {
        unsafe {
            core::ptr::addr_of_mut!(STREAM_READ_CORE).write_volatile(fake_stream_read_core);
        }
    }

    #[test]
    fn stores_decoded_word_when_stream_reader_succeeds() {
        let _lock = STREAM_READ_CORE_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        install_core();
        let _reset = CoreReset;
        unsafe {
            core::ptr::addr_of_mut!(FILL).write([0x12, 0x34, 0x56, 0x78]);
            core::ptr::addr_of_mut!(STATUS).write(0);
        }

        let mut out = 0;
        let status = unsafe { stream_read_be32_or_zero(0x0801_2345, &mut out) };

        assert_eq!(status, 1);
        assert_eq!(out, 0x1234_5678);
    }

    #[test]
    fn zeroes_output_when_stream_reader_fails() {
        let _lock = STREAM_READ_CORE_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        install_core();
        let _reset = CoreReset;
        unsafe {
            core::ptr::addr_of_mut!(FILL).write([0xde, 0xad, 0xbe, 0xef]);
            core::ptr::addr_of_mut!(STATUS).write(-3);
        }

        let mut out = 0xfeed_face;
        let status = unsafe { stream_read_be32_or_zero(0, &mut out) };

        assert_eq!(status, 0);
        assert_eq!(out, 0);
    }
}
