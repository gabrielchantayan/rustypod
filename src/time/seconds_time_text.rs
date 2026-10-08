//! Shared-buffer time text: FUN_081404b4 @ 0x081404b4.
//!
//! True extent 80 bytes (0x081404b4..0x08140504): 76 code bytes and
//! the buffer literal 0x08ad2ce8. Two outbound plain BLs, zero predicated
//! BLs, one virtual BLX; two inbound plain BLs (0x0829b678, 0x0829b758),
//! zero predicated BLs, independently decoded from raw firmware words.
//! Fetch singleton state, convert the pointed-to unsigned Unix seconds to
//! a calendar record, then invoke vtable slot 33 with the shared buffer,
//! capacity 32, selector 17, and the record. Ignore the virtual return and
//! return the shared buffer. No null checks or allocation.
//!
//! Deviations: reuse the two existing Rust callees. Host builds use native
//! pointer-width vtable fields and a local shared buffer instead of firmware
//! RAM. Scratch padding remains unspecified as in firmware; incoming r1-r3
//! are not semantic arguments. The converter produces the calendar fields.

use super::datetime::DateTime;
use super::unix_to_datetime::unix_seconds_to_datetime;
use crate::app::singleton_state::singleton_state_get;

pub type FormatTime = unsafe extern "C" fn(*mut TimeTextService, *mut u8, u32, u32, *const DateTime) -> u32;

#[repr(C)]
pub struct TimeTextVtable {
    pub preceding: [usize; 33],
    pub format: FormatTime,
}

#[repr(C)]
pub struct TimeTextService {
    pub vtable: *const TimeTextVtable,
}

#[cfg(not(target_os = "none"))]
static mut HOST_TIME_TEXT: [u8; 32] = [0; 32];

#[inline(always)]
fn shared_buffer() -> *mut u8 {
    #[cfg(target_os = "none")]
    { 0x08ad_2ce8 as *mut u8 }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of_mut!(HOST_TIME_TEXT).cast() }
}

/// # Safety
/// `seconds` must address an aligned readable u32. The singleton state must
/// be a live service with callable slot 33, accepting a ten-byte DateTime
/// and the shared writable 32-byte buffer. Calls must be externally serialized.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn seconds_time_text(seconds: *const u32) -> *const u8 {
    let service = singleton_state_get() as usize as *mut TimeTextService;
    // Preserve the original three-word scratch extent and alignment.
    let mut calendar = core::mem::MaybeUninit::<[u32; 3]>::uninit();
    let datetime = calendar.as_mut_ptr().cast::<DateTime>();
    unix_seconds_to_datetime(seconds.read(), datetime);
    let buffer = shared_buffer();
    ((*(*service).vtable).format)(service, buffer, 32, 17, datetime);
    buffer
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::time::unix_to_datetime::{DAY_NUMBER_TO_DATETIME, DAY_NUMBER_TO_DATETIME_TEST_LOCK};
    use crate::app::singleton_state::{HOST_SINGLETON_STATE_BASE, tests::ACCESS_TEST_LOCK};

    unsafe extern "C" fn calendar_date(_: u32, out: *mut DateTime) {
        out.write(DateTime { second: 0, minute: 0, hour: 0, day: 1, month: 1,
            reserved: 0, year: 1970, weekday: 4, reserved2: 0 });
    }

    unsafe extern "C" fn render(_: *mut TimeTextService, buffer: *mut u8, capacity: u32,
        selector: u32, datetime: *const DateTime) -> u32 {
        assert_eq!((capacity, selector), (32, 17));
        let dt = datetime.read();
        let text = std::format!("{:02}:{:02}:{:02}", dt.hour, dt.minute, dt.second);
        core::ptr::copy_nonoverlapping(text.as_ptr(), buffer, text.len());
        buffer.add(text.len()).write(0);
        0xdead_beef // Must not replace the shared-buffer return.
    }

    #[test]
    fn unsigned_boundaries_and_shared_buffer_replacement() {
        let _singleton = ACCESS_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _calendar = DAY_NUMBER_TO_DATETIME_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _resolver = crate::object_word_payload_resolve::tests::PROCESSOR_TEST_LOCK.lock();
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::SECONDS_TIME_TEXT, 4096) else { return };
        let vtable = TimeTextVtable { preceding: [0; 33], format: render };
        unsafe {
            let base = slab.cast::<u32>();
            let service = slab.add(64).cast::<TimeTextService>();
            service.write(TimeTextService { vtable: &vtable });
            base.add(6).write(service as usize as u32);
            let old_base = HOST_SINGLETON_STATE_BASE;
            let old_convert = DAY_NUMBER_TO_DATETIME;
            HOST_SINGLETON_STATE_BASE = slab;
            DAY_NUMBER_TO_DATETIME = calendar_date;
            let mut previous: *const u8 = core::ptr::null();
            for (seconds, expected) in [(0, "00:00:00"), (59, "00:00:59"),
                (60, "00:01:00"), (3599, "00:59:59"), (3600, "01:00:00"),
                (86399, "23:59:59"), (86400, "00:00:00"), (u32::MAX, "06:28:15")] {
                let text = seconds_time_text(&seconds);
                assert_eq!(std::ffi::CStr::from_ptr(text.cast()).to_str().unwrap(), expected);
                if !previous.is_null() { assert_eq!(previous, text); }
                previous = text;
                let mut object = [0u32; 14];
                object[7..11].copy_from_slice(&[12345, 67890, 3600, seconds]);
                assert_eq!(crate::util::object_payload_time_text::object_payload_time_text(object.as_mut_ptr()), text);
                assert_eq!(std::ffi::CStr::from_ptr(text.cast()).to_str().unwrap(), expected);
                object[8] = seconds;
                object[10] = 12345;
                assert_eq!(crate::util::object_word_payload_dispatch::object_word_payload_dispatch(object.as_mut_ptr()), text);
                assert_eq!(std::ffi::CStr::from_ptr(previous.cast()).to_str().unwrap(), expected);
            }
            DAY_NUMBER_TO_DATETIME = old_convert;
            HOST_SINGLETON_STATE_BASE = old_base;
        }
    }
}
