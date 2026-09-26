//! `basic_ostream::flush` stream-buffer synchronization.

/// `ostream_flush` — original: `FUN_083d8344` @ load address **0x083d8344**
/// (76 bytes).
///
/// Raw ARM establishes the exact extent 0x083d8344..0x083d838f: `push
/// {r4,lr}` opens at the entry and `pop {r4,pc}` ends at 0x083d838c; the next
/// real function begins at 0x083d8390. Whole-image ARM B/BL-immediate decoding
/// finds two inbound predicated `bl` sites (0x083d8248 and 0x083d8484), no
/// inbound plain `bl` sites. The body makes one indirect `blx` through the
/// streambuf vtable's +0x34 slot and one `bleq` to `basic_ios::setstate` at
/// 0x083e7898. It obtains the vtable-relative `basic_ios` base, calls
/// `pubsync`, and sets `badbit` when it returns exactly -1 before returning the
/// original ostream pointer. Deliberate deviation: host builds replace both
/// target calls with hooks because target function pointers are 32-bit.
///
/// # Safety
///
/// `ostream` must be a valid target-layout `basic_ostream`. Its descriptor,
/// streambuf, and streambuf virtual sync slot must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ostream_flush(ostream: *mut u8) -> *mut u8 {
    let vtable = (ostream as *const u32).read() as usize as *const i32;
    let streambuf = (ostream.offset(vtable.offset(-3).read() as isize).add(0x34) as *const u32).read() as usize as *mut u8;

    if !streambuf.is_null() && streambuf_pubsync(streambuf) == -1 {
        let basic_ios = ostream.offset(vtable.offset(-3).read() as isize);
        basic_ios_setstate(basic_ios, 1);
    }

    ostream
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn streambuf_pubsync(streambuf: *mut u8) -> i32 {
    let vtable = (streambuf as *const u32).read() as usize as *const u32;
    let sync: unsafe extern "C" fn(*mut u8) -> i32 = core::mem::transmute(vtable.add(0x34 / 4).read() as usize);
    sync(streambuf)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn basic_ios_setstate(basic_ios: *mut u8, state: u32) {
    let setstate: unsafe extern "C" fn(*mut u8, u32) = core::mem::transmute(0x083e_7898usize);
    setstate(basic_ios, state);
}

#[cfg(not(target_os = "none"))]
pub(crate) type StreambufPubsyncHook = unsafe extern "C" fn(*mut u8) -> i32;
#[cfg(not(target_os = "none"))]
pub(crate) type BasicIosSetstateHook = unsafe extern "C" fn(*mut u8, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_streambuf_pubsync(_streambuf: *mut u8) -> i32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_basic_ios_setstate(_basic_ios: *mut u8, _state: u32) {}

#[cfg(not(target_os = "none"))]
pub(crate) static mut STREAMBUF_PUBSYNC: StreambufPubsyncHook = unavailable_streambuf_pubsync;
#[cfg(not(target_os = "none"))]
pub(crate) static mut BASIC_IOS_SETSTATE: BasicIosSetstateHook = unavailable_basic_ios_setstate;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn streambuf_pubsync(streambuf: *mut u8) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(STREAMBUF_PUBSYNC))(streambuf)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn basic_ios_setstate(basic_ios: *mut u8, state: u32) {
    core::ptr::read_volatile(core::ptr::addr_of!(BASIC_IOS_SETSTATE))(basic_ios, state)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SYNC_RESULT: i32 = 0;
    static mut SYNC_STREAMBUF: *mut u8 = ptr::null_mut();
    static mut SETSTATE_IOS: *mut u8 = ptr::null_mut();
    static mut SETSTATE_VALUE: u32 = 0;

    unsafe extern "C" fn record_pubsync(streambuf: *mut u8) -> i32 {
        SYNC_STREAMBUF = streambuf;
        SYNC_RESULT
    }

    unsafe extern "C" fn record_setstate(basic_ios: *mut u8, state: u32) {
        SETSTATE_IOS = basic_ios;
        SETSTATE_VALUE = state;
    }

    unsafe fn fixture() -> Option<(*mut u8, *mut u8, *mut u8)> {
        let slab = try_map_u32_slab(hints::OSTREAM_FLUSH, 0x200)?;
        let vtable = slab.add(0x0c);
        (vtable.offset(-3) as *mut i32).write(0x40);
        let ostream = slab.add(0x40);
        ostream.cast::<u32>().write(vtable as usize as u32);
        let basic_ios = ostream.add(0x40);
        let streambuf = slab.add(0x180);
        basic_ios.add(0x34).cast::<u32>().write(streambuf as usize as u32);
        Some((ostream, basic_ios, streambuf))
    }

    #[test]
    fn synchronizes_nonnull_streambuf_and_returns_ostream() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some((ostream, basic_ios, streambuf)) = (unsafe { fixture() }) else { return };
        unsafe {
            STREAMBUF_PUBSYNC = record_pubsync;
            BASIC_IOS_SETSTATE = record_setstate;
            SYNC_RESULT = 0;
            SYNC_STREAMBUF = ptr::null_mut();
            SETSTATE_IOS = ptr::null_mut();
            SETSTATE_VALUE = 0;
            assert_eq!(ostream_flush(ostream), ostream);
            assert_eq!(SYNC_STREAMBUF, streambuf);
            assert!(SETSTATE_IOS.is_null());
        }
        let _ = basic_ios;
    }

    #[test]
    fn sync_failure_sets_only_badbit_on_vtable_relative_ios_base() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some((ostream, basic_ios, _)) = (unsafe { fixture() }) else { return };
        unsafe {
            STREAMBUF_PUBSYNC = record_pubsync;
            BASIC_IOS_SETSTATE = record_setstate;
            SYNC_RESULT = -1;
            SETSTATE_IOS = ptr::null_mut();
            SETSTATE_VALUE = 0;
            ostream_flush(ostream);
            assert_eq!(SETSTATE_IOS, basic_ios);
            assert_eq!(SETSTATE_VALUE, 1);
        }
    }

    #[test]
    fn null_streambuf_skips_both_calls() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let Some((ostream, _, _)) = (unsafe { fixture() }) else { return };
        unsafe {
            STREAMBUF_PUBSYNC = record_pubsync;
            BASIC_IOS_SETSTATE = record_setstate;
            SYNC_STREAMBUF = ptr::null_mut();
            SETSTATE_IOS = ptr::null_mut();
            ostream.add(0x40 + 0x34).cast::<u32>().write(0);
            assert_eq!(ostream_flush(ostream), ostream);
            assert!(SYNC_STREAMBUF.is_null());
            assert!(SETSTATE_IOS.is_null());
        }
    }
}
