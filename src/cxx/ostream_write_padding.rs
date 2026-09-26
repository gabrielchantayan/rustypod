//! `basic_ostream` fill-character padding helper.
//!
//! The target's `basic_ostream` object uses a vtable-relative base: its vtable
//! word's preceding `i32` at `-0x0c` is added to `this` before the streambuf
//! pointer and fill character are read.

/// `ostream_write_padding` — original: `FUN_083d8390` @ load address
/// **0x083d8390** (80 bytes).
///
/// Raw ARM establishes the exact extent 0x083d8390..0x083d83dc: the next
/// separately linked helper begins at 0x083d83e0. Whole-image ARM
/// B/BL-immediate decoding finds two direct inbound calls, both unconditional
/// plain `bl` at 0x083b53a0 and 0x083b53f8; zero are predicated. The body has
/// one unconditional `bl`, to the independently named `streambuf_sputc` at
/// 0x083da5c8. It writes the fill character at the vtable-relative `+0x3c`
/// through the streambuf at `+0x34` until `count` bytes have been accepted,
/// or until `streambuf_sputc` returns exactly -1, and returns the count
/// written. Negative counts return unchanged. No ARM deviations; host tests
/// replace the target-width streambuf call with a hook.
///
/// # Safety
///
/// `ostream` must point to a valid target-layout basic ostream object. Its
/// vtable-relative base, streambuf pointer, and fill character must be valid;
/// the streambuf must satisfy `streambuf_sputc`'s safety contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ostream_write_padding(ostream: *mut u8, count: i32) -> i32 {
    let vtable = (ostream as *const u32).read() as usize as *const i32;
    let stream_base = ostream.offset(vtable.offset(-3).read() as isize);
    let streambuf = (stream_base.add(0x34) as *const u32).read() as usize as *mut u8;
    let fill_character = stream_base.add(0x3c).read() as u32;
    let mut written = 0;

    while written < count {
        if streambuf_sputc(streambuf, fill_character) == -1 {
            return written;
        }
        written += 1;
    }

    count
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn streambuf_sputc(streambuf: *mut u8, character: u32) -> i32 {
    crate::cxx::string::streambuf_sputc(streambuf, character)
}

#[cfg(not(target_arch = "arm"))]
pub(crate) type StreambufSputcHook = unsafe extern "C" fn(*mut u8, u32) -> i32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn unavailable_streambuf_sputc(_streambuf: *mut u8, _character: u32) -> i32 {
    -1
}

#[cfg(not(target_arch = "arm"))]
pub(crate) static mut STREAMBUF_SPUTC: StreambufSputcHook = unavailable_streambuf_sputc;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn streambuf_sputc(streambuf: *mut u8, character: u32) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(STREAMBUF_SPUTC))(streambuf, character)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use std::sync::Mutex;
    use std::{vec, vec::Vec};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CALLS: Mutex<Vec<(usize, u32)>> = Mutex::new(Vec::new());
    static mut FAILURE_AFTER: i32 = -1;

    unsafe extern "C" fn recording_sputc(streambuf: *mut u8, character: u32) -> i32 {
        let mut calls = CALLS.lock().unwrap_or_else(|poison| poison.into_inner());
        let fails = calls.len() as i32 == FAILURE_AFTER;
        calls.push((streambuf as usize, character));
        if fails { -1 } else { character as i32 }
    }

    unsafe fn fixture(hint: usize) -> Option<*mut u8> {
        let slab = try_map_u32_slab(hint, 0x100)?;
        let vtable = slab.add(0x0c);
        (vtable.offset(-3) as *mut i32).write(0);
        let ostream = slab.add(0x20);
        (ostream as *mut u32).write(vtable as usize as u32);
        (ostream.add(0x34) as *mut u32).write(0x1234_5678);
        ostream.add(0x3c).write(0xa5);
        Some(ostream)
    }

    #[test]
    fn writes_each_requested_fill_character() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some(ostream) = (unsafe { fixture(hints::OSTREAM_WRITE_PADDING_COMPLETE) }) else { return };
        unsafe { STREAMBUF_SPUTC = recording_sputc; FAILURE_AFTER = -1; }
        CALLS.lock().unwrap_or_else(|poison| poison.into_inner()).clear();

        assert_eq!(unsafe { ostream_write_padding(ostream, 3) }, 3);
        assert_eq!(*CALLS.lock().unwrap_or_else(|poison| poison.into_inner()), vec![(0x1234_5678, 0xa5); 3]);
    }

    #[test]
    fn stops_only_at_negative_one_and_preserves_nonpositive_counts() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some(ostream) = (unsafe { fixture(hints::OSTREAM_WRITE_PADDING_FAILURE) }) else { return };
        unsafe { STREAMBUF_SPUTC = recording_sputc; FAILURE_AFTER = 2; }
        CALLS.lock().unwrap_or_else(|poison| poison.into_inner()).clear();

        assert_eq!(unsafe { ostream_write_padding(ostream, 5) }, 2);
        assert_eq!(CALLS.lock().unwrap_or_else(|poison| poison.into_inner()).len(), 3);
        assert_eq!(unsafe { ostream_write_padding(ostream, 0) }, 0);
        assert_eq!(unsafe { ostream_write_padding(ostream, -4) }, -4);
        assert_eq!(CALLS.lock().unwrap_or_else(|poison| poison.into_inner()).len(), 3);
    }
}
