//! Voice-memo duration query — `FUN_081a4b88` @ **0x081a4b88**.
//!
//! True extent: **160 bytes**, 0x081a4b88..0x081a4c28 (152 code bytes,
//! eight literal bytes; next function begins with push at 0x081a4c28).
//! Raw aligned A32 decoding: two inbound plain BLs, zero predicated BLs;
//! four outgoing plain BLs, zero predicated BLs, one virtual BLX and one
//! tail B to string_object_raw_payload @ 0x082a538c.
//!
//! When active (+0x8a), query the recorder at +0x20 through vtable +0xc0,
//! divide its counter by 1000, then add wrapping 60 * interval * count(+0xd0).
//! The interval helper @ 0x081a41ac returns 120 or 2 and preserves r1;
//! Ghidra incorrectly models that register pair as a 64-bit return.
//! Selector 'Str ' formats into the StringObject at +0x78 and returns its
//! raw payload; 'DtTm' converts into the ten-byte calendar record at +0x80.
//! Unknown selectors return NULL, but still perform the active counter query.
//!
//! Deviations: retained seconds are a Rust local, not an implicit r1 result.
//! Unported interval/format helpers use volatile firmware seams; the virtual
//! counter query is also replaceable on hosts. Host payload access uses the
//! target-width word at +0x7c rather than a host-width StringObject layout.

use crate::time::{datetime::DateTime, unix_to_datetime::unix_seconds_to_datetime};

pub const DURATION_STRING: u32 = 0x5374_7220;
pub const DURATION_DATETIME: u32 = 0x4474_546d;

#[derive(Clone, Copy)]
pub struct VoiceMemoDurationOps {
    pub counter: unsafe extern "C" fn(*mut u8) -> u32,
    pub interval: unsafe extern "C" fn(*mut u8, u32) -> u32,
    pub format: unsafe extern "C" fn(*mut u8, u32, *mut u8),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn counter(controller: *mut u8) -> u32 {
    let recorder = controller.add(0x20).cast::<u32>().read() as usize as *mut u32;
    let vtable = recorder.read() as usize as *const u32;
    let query: unsafe extern "C" fn(*mut u32) -> u32 =
        core::mem::transmute(vtable.add(0xc0 / 4).read() as usize);
    query(recorder)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn interval(controller: *mut u8, seconds: u32) -> u32 {
    let query: unsafe extern "C" fn(*mut u8, u32) -> u32 = core::mem::transmute(0x081a_41acusize);
    query(controller, seconds)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn format(controller: *mut u8, seconds: u32, out: *mut u8) {
    let format: unsafe extern "C" fn(*mut u8, u32, *mut u8) = core::mem::transmute(0x081a_3e48usize);
    format(controller, seconds, out)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn counter(_: *mut u8) -> u32 { panic!("missing recorder counter model") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn interval(_: *mut u8, _: u32) -> u32 { panic!("missing voice memo interval model") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn format(_: *mut u8, _: u32, _: *mut u8) { panic!("missing voice memo formatter model") }

pub static mut VOICE_MEMO_DURATION_OPS: VoiceMemoDurationOps = VoiceMemoDurationOps { counter, interval, format };

/// `controller` must be aligned and writable through +0xd4; active controllers
/// must contain a valid recorder. Installed operations must satisfy retailOS ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn voice_memo_duration_query(controller: *mut u8, selector: u32) -> *mut u8 {
    let ops = core::ptr::addr_of!(VOICE_MEMO_DURATION_OPS).read_volatile();
    let mut seconds = 0;
    if controller.add(0x8a).read() != 0 {
        seconds = crate::runtime::rt_div::__rt_udiv((ops.counter)(controller), 1000);
        let interval = (ops.interval)(controller, seconds);
        seconds = seconds.wrapping_add(controller.add(0xd0).cast::<u32>().read()
            .wrapping_mul(interval).wrapping_mul(60));
    }
    match selector {
        DURATION_STRING => {
            (ops.format)(controller, seconds, controller.add(0x78));
            #[cfg(target_os = "none")]
            { crate::cxx::string_object::string_object_raw_payload(controller.add(0x78).cast()) }
            #[cfg(not(target_os = "none"))]
            { controller.add(0x7c).cast::<u32>().read() as usize as *mut u8 }
        }
        DURATION_DATETIME => {
            let out = controller.add(0x80);
            unix_seconds_to_datetime(seconds, out.cast::<DateTime>());
            out
        }
        _ => core::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    static INTERVAL: AtomicU32 = AtomicU32::new(0);
    static CALLS: AtomicU32 = AtomicU32::new(0);
    static SECONDS: AtomicU32 = AtomicU32::new(0);
    unsafe extern "C" fn query(_: *mut u8) -> u32 {
        CALLS.fetch_add(1, Ordering::Relaxed);
        COUNTER.load(Ordering::Relaxed)
    }
    unsafe extern "C" fn scale(_: *mut u8, _: u32) -> u32 { INTERVAL.load(Ordering::Relaxed) }
    unsafe extern "C" fn render(_: *mut u8, seconds: u32, out: *mut u8) {
        SECONDS.store(seconds, Ordering::Relaxed);
        out.add(4).cast::<u32>().write(if seconds == 0 { 0 } else { 0x12345678 });
    }
    unsafe extern "C" fn calendar(_: u32, out: *mut DateTime) {
        core::ptr::write_bytes(out.cast::<u8>(), 0, 10);
    }
    struct Restore(VoiceMemoDurationOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { core::ptr::addr_of_mut!(VOICE_MEMO_DURATION_OPS).write(self.0) }; }
    }
    #[test]
    fn inactive_zero_active_scaling_wrapping_and_unknown_selectors() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let _restore = Restore(core::ptr::addr_of!(VOICE_MEMO_DURATION_OPS).read());
            core::ptr::addr_of_mut!(VOICE_MEMO_DURATION_OPS).write(VoiceMemoDurationOps { counter: query, interval: scale, format: render });
            let mut storage = [0u32; 53];
            let controller = storage.as_mut_ptr().cast::<u8>();
            CALLS.store(0, Ordering::Relaxed);
            assert!(voice_memo_duration_query(controller, DURATION_STRING).is_null());
            assert_eq!(SECONDS.load(Ordering::Relaxed), 0);
            assert_eq!(CALLS.load(Ordering::Relaxed), 0);
            controller.add(0x8a).write(0xff);
            for (ticks, interval, count, expected) in [
                (999, 120, 0, 0), (1001, 2, 3, 361),
                (1234999, 120, 2, 15634), (u32::MAX, 120, u32::MAX, 4287767),
            ] {
                COUNTER.store(ticks, Ordering::Relaxed);
                INTERVAL.store(interval, Ordering::Relaxed);
                controller.add(0xd0).cast::<u32>().write(count);
                let result = voice_memo_duration_query(controller, DURATION_STRING);
                assert_eq!(SECONDS.load(Ordering::Relaxed), expected);
                assert_eq!(result as usize, if expected == 0 { 0 } else { 0x12345678 });
            }
            let before = CALLS.load(Ordering::Relaxed);
            assert!(voice_memo_duration_query(controller, 0).is_null());
            assert_eq!(CALLS.load(Ordering::Relaxed), before + 1);
        }
    }
    #[test]
    fn datetime_uses_embedded_target_record_and_real_time_decomposition() {
        use crate::time::unix_to_datetime::{DAY_NUMBER_TO_DATETIME, DAY_NUMBER_TO_DATETIME_TEST_LOCK};
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _calendar_lock = DAY_NUMBER_TO_DATETIME_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let old = core::ptr::addr_of!(DAY_NUMBER_TO_DATETIME).read();
            core::ptr::addr_of_mut!(DAY_NUMBER_TO_DATETIME).write(calendar);
            let _restore = Restore(core::ptr::addr_of!(VOICE_MEMO_DURATION_OPS).read());
            core::ptr::addr_of_mut!(VOICE_MEMO_DURATION_OPS).write(VoiceMemoDurationOps { counter: query, interval: scale, format: render });
            let mut storage = [0u32; 53];
            let controller = storage.as_mut_ptr().cast::<u8>();
            controller.add(0x8a).write(1);
            COUNTER.store(3661999, Ordering::Relaxed);
            INTERVAL.store(2, Ordering::Relaxed);
            let out = voice_memo_duration_query(controller, DURATION_DATETIME);
            assert_eq!(out, controller.add(0x80));
            assert_eq!(core::slice::from_raw_parts(out, 3), &[1, 1, 1]);
            assert_eq!(controller.add(0x8a).read(), 1);
            core::ptr::addr_of_mut!(DAY_NUMBER_TO_DATETIME).write(old);
        }
    }
}
